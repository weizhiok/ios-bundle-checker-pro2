import SwiftUI
import Security
import Foundation
import Darwin // 必须引入 Darwin 以使用 dlsym

// ========================================================================
// 🛠️ 核心修复 V5: 使用裸指针 (RawPointer) 绕过 C 类型检查
// ========================================================================

// 1. 手动定义 Dl_info 结构体 (C 内存布局)
struct Local_Dl_info {
    var dli_fname: UnsafePointer<CChar>?  // 镜像路径
    var dli_fbase: UnsafeMutableRawPointer? // 镜像基地址
    var dli_sname: UnsafePointer<CChar>?  // 符号名称
    var dli_saddr: UnsafeMutableRawPointer? // 符号地址
}

// 2. 动态调用 dladdr 的封装函数
func safe_dladdr(_ addr: UnsafeRawPointer, _ info: UnsafeMutablePointer<Local_Dl_info>) -> Int32 {
    // RTLD_DEFAULT 在 macOS/iOS 上通常是 -2
    let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
    
    // 动态查找 "dladdr" 符号
    guard let sym = dlsym(RTLD_DEFAULT, "dladdr") else {
        return 0
    }
    
    // 【关键修改】: 将第二个参数定义为 UnsafeMutableRawPointer (裸指针)
    // 这样编译器就不会抱怨 "Local_Dl_info cannot be used with @convention(c)"
    typealias DlAddrFunc = @convention(c) (UnsafeRawPointer, UnsafeMutableRawPointer) -> Int32
    
    // 将 dlsym 返回的 void* 强转为我们的函数类型
    let dladdr_real = unsafeBitCast(sym, to: DlAddrFunc.self)
    
    // 将传入的结构体指针转为裸指针
    let infoRaw = UnsafeMutableRawPointer(info)
    
    // 执行调用
    return dladdr_real(addr, infoRaw)
}

// 3. Security 函数映射
typealias SecTaskRef = AnyObject

@_silgen_name("SecTaskCreateFromSelf")
func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> SecTaskRef?

@_silgen_name("SecTaskCopySigningIdentifier")
func SecTaskCopySigningIdentifier(_ task: SecTaskRef, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFString?

// ========================================================================

@main
struct BundleCheckerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var results: [ResultItem] = []
    @State private var isLoading = true

    struct ResultItem: Hashable, Identifiable {
        let id = UUID()
        let method: String
        let value: String
        let detail: String
        let status: Status
    }

    enum Status {
        case safe
        case suspicious
        case warning
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 终极攻防 V5")
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
            
            if isLoading {
                VStack {
                    ProgressView()
                        .padding()
                    Text("正在进行底层取证...")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
                .padding()
            } else {
                List {
                    ForEach(results) { item in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.method)
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.gray)
                                
                                Text(item.value)
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(colorForStatus(item.status))
                                    .textSelection(.enabled)
                                
                                if !item.detail.isEmpty {
                                    Text(item.detail)
                                        .font(.system(size: 10))
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.plain)
            }
        }
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                performAllChecks()
                isLoading = false
            }
        }
    }

    func colorForStatus(_ status: Status) -> Color {
        switch status {
        case .safe: return .primary
        case .suspicious: return .red
        case .warning: return .orange
        }
    }

    // ========================================================================
    // 🔍 核心检测逻辑
    // ========================================================================
    func performAllChecks() {
        var items: [ResultItem] = []
        
        // --- 0. 确立基准 (SecTask) ---
        let kernelID = getSecTaskSigningIdentifier()
        let cleanKernelID = stripTeamID(kernelID)
        
        // --- 1. Objective-C API ---
        let nsBundleID = Bundle.main.bundleIdentifier ?? "nil"
        items.append(ResultItem(
            method: "1. [OC API] Bundle.main",
            value: nsBundleID,
            detail: "最易被 Hook",
            status: nsBundleID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 2. CoreFoundation C API ---
        let cfBundleID = getCFBundleIdentifier()
        items.append(ResultItem(
            method: "2. [C API] CFBundleGetIdentifier",
            value: cfBundleID,
            detail: "绕过 OC Runtime",
            status: cfBundleID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 3. NSDictionary 读取 ---
        let dictID = getDictFromInfo()
        items.append(ResultItem(
            method: "3. [Cocoa IO] Info.plist 字典",
            value: dictID,
            detail: "易被文件读取 Hook",
            status: dictID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 4. fopen 直接读取 ---
        let fopenID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(
            method: "4. [Libc IO] fopen 直接读取",
            value: fopenID,
            detail: "绕过 Cocoa IO",
            status: fopenID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 5. SecTask 内核层 ---
        items.append(ResultItem(
            method: "5. [内核层] SecTask",
            value: kernelID,
            detail: "基于 Entitlements (权威)",
            status: .safe
        ))
        
        // --- 6. 描述文件 ---
        let provID = getMobileProvisionID()
        let (provStatus, provDetail) = analyzeProvisionID(provID: provID, standard: cleanKernelID)
        items.append(ResultItem(
            method: "6. [证书层] mobileprovision",
            value: provID,
            detail: provDetail,
            status: provStatus
        ))
        
        // --- 7. Runtime 完整性检测 ---
        let (runtimeStatus, runtimeMsg) = checkRuntimeIntegrity()
        items.append(ResultItem(
            method: "7. [Runtime] 方法地址检测",
            value: runtimeStatus ? "Safe" : "⚠️ Suspicious",
            detail: runtimeMsg,
            status: runtimeStatus ? .safe : .suspicious
        ))

        self.results = items
    }
    
    // --- 辅助函数 ---
    
    func stripTeamID(_ fullID: String) -> String {
        let components = fullID.components(separatedBy: ".")
        if components.count > 1 && components[0].count == 10 {
            return components.dropFirst().joined(separator: ".")
        }
        return fullID
    }
    
    func analyzeProvisionID(provID: String, standard: String) -> (Status, String) {
        if provID.contains("未找到") || provID.contains("错误") { return (.warning, "无法读取文件") }
        if provID == standard { return (.safe, "完全一致") }
        if provID.hasSuffix("." + standard) { return (.safe, "一致 (含 TeamID)") }
        if provID.contains("*") { return (.warning, "通配符证书") }
        return (.suspicious, "与内核ID不符")
    }

    // --- 实现: CFBundleGetIdentifier ---
    func getCFBundleIdentifier() -> String {
        let mainBundle = CFBundleGetMainBundle()
        if let idRef = CFBundleGetIdentifier(mainBundle) {
            return idRef as String
        }
        return "Fail"
    }

    // --- 实现: NSDictionary ---
    func getDictFromInfo() -> String {
        if let path = Bundle.main.path(forResource: "Info", ofType: "plist"),
           let dict = NSDictionary(contentsOfFile: path),
           let id = dict["CFBundleIdentifier"] as? String {
            return id
        }
        return "Fail"
    }

    // --- 实现: fopen ---
    func getBundleIDFromPlistUsingFopen() -> String {
        guard let path = Bundle.main.path(forResource: "Info", ofType: "plist") else { return "No Path" }
        guard let file = fopen(path, "r") else { return "fopen Fail" }
        defer { fclose(file) }
        fseek(file, 0, SEEK_END)
        let size = ftell(file)
        fseek(file, 0, SEEK_SET)
        if size <= 0 { return "Empty" }
        var buffer = [CChar](repeating: 0, count: Int(size) + 1)
        fread(&buffer, 1, Int(size), file)
        let content = String(cString: buffer)
        
        if let range = content.range(of: "CFBundleIdentifier") {
            let sub = content[range.upperBound...]
            if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                return String(sub[start.upperBound..<end.lowerBound])
            }
        }
        return "Parse Fail"
    }

    // --- 实现: SecTask ---
    func getSecTaskSigningIdentifier() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else { return "SecTask Fail" }
        if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
            return idRef as String
        }
        return "Unknown"
    }
    
    // --- 实现: Provision ---
    func getMobileProvisionID() -> String {
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return "未找到 (模拟器/无签)"
        }
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let content = String(data: data, encoding: .isoLatin1) ?? ""
            if let range = content.range(of: "<key>application-identifier</key>") {
                let sub = content[range.upperBound...]
                if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                    return String(sub[start.upperBound..<end.lowerBound])
                }
            }
        } catch { return "Read Error" }
        return "Not Found"
    }
    
    // --- 实现: Runtime Check (dlsym + RawPointer) ---
    func checkRuntimeIntegrity() -> (Bool, String) {
        let selector = #selector(getter: Bundle.bundleIdentifier)
        guard let method = class_getInstanceMethod(Bundle.self, selector) else {
            return (false, "Method Missing")
        }
        let imp = method_getImplementation(method)
        
        // 准备 Local_Dl_info 结构体
        var info = Local_Dl_info()
        
        // 使用动态查找的 safe_dladdr
        let impPtr = UnsafeRawPointer(imp)
        
        if safe_dladdr(impPtr, &info) != 0 {
            if let fnamePtr = info.dli_fname {
                let fname = String(cString: fnamePtr)
                // 检查镜像路径
                if fname.contains("CoreFoundation") || fname.contains("Foundation") || fname.contains("libswift") {
                    return (true, "IMP in System Framework")
                } else {
                    let libName = URL(fileURLWithPath: fname).lastPathComponent
                    return (false, "Hooked by: \(libName)")
                }
            }
        }
        return (false, "dladdr Failed")
    }
}
