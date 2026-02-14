import SwiftUI
import Security
import Foundation
import MachO // 用于底层内存检测

// ========================================================================
// 🛠️ 核心黑魔法区：C-API 映射与底层声明
// ========================================================================

typealias SecTaskRef = AnyObject

@_silgen_name("SecTaskCreateFromSelf")
func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> SecTaskRef?

@_silgen_name("SecTaskCopySigningIdentifier")
func SecTaskCopySigningIdentifier(_ task: SecTaskRef, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFString?

// 引入 dladdr 用于检测方法是否被 Hook
@_silgen_name("dladdr")
func dladdr(_ addr: UnsafeRawPointer, _ info: UnsafeMutablePointer<Dl_info>) -> Int32

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
        let method: String      // 检测手段名称
        let value: String       // 获取到的值
        let detail: String      // 补充说明（如：来自哪个库）
        let status: Status      // 状态
    }

    enum Status {
        case safe       // 黑色 (正常)
        case suspicious // 红色 (被篡改或不一致)
        case warning    // 橙色 (非致命不一致，如TeamID前缀)
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 全维攻防检测")
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
            
            if isLoading {
                ProgressView("正在进行深度取证...")
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
            // 延时一点执行以免阻塞 UI 渲染
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                performAllChecks()
                isLoading = false
            }
        }
    }

    func colorForStatus(_ status: Status) -> Color {
        switch status {
        case .safe: return .primary // 黑色/深色模式白
        case .suspicious: return .red
        case .warning: return .orange
        }
    }

    // ========================================================================
    // 🔍 核心检测逻辑
    // ========================================================================
    func performAllChecks() {
        var items: [ResultItem] = []
        
        // --- 0. 确立“真理之源” ---
        // 我们假设 SecTask (内核层) 是最难被篡改的，以此为基准
        let kernelID = getSecTaskSigningIdentifier()
        let cleanKernelID = stripTeamID(kernelID) // 去除 TeamID 的纯净版
        
        // --- 1. Objective-C API 层 (最常被 Hook) ---
        let nsBundleID = Bundle.main.bundleIdentifier ?? "nil"
        items.append(ResultItem(
            method: "1. [OC API] Bundle.main",
            value: nsBundleID,
            detail: "容易被 Method Swizzling 篡改",
            status: nsBundleID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 2. CoreFoundation C API 层 ---
        // 你的代码里提到了 Hook CFBundleGetIdentifier，这里进行验证
        let cfBundleID = getCFBundleIdentifier()
        items.append(ResultItem(
            method: "2. [C API] CFBundleGetIdentifier",
            value: cfBundleID,
            detail: "底层 C 函数，绕过 NSBundle",
            status: cfBundleID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 3. Info.plist 字典读取 (Cocoa IO) ---
        let dictID = getDictFromInfo()
        items.append(ResultItem(
            method: "3. [Cocoa IO] NSDictionary 读取",
            value: dictID,
            detail: "对应 dictionaryWithContentsOfFile 注入",
            status: dictID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 4. 裸文件流读取 (C IO) ---
        // 绕过所有 Cocoa 层的 Hook
        let fopenID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(
            method: "4. [Libc IO] fopen 直接读取",
            value: fopenID,
            detail: "直接解析二进制/XML文件流",
            status: fopenID == cleanKernelID ? .safe : .suspicious
        ))
        
        // --- 5. 内核授权信息 (SecTask) ---
        // 这是最权威的
        items.append(ResultItem(
            method: "5. [内核层] SecTask Entitlements",
            value: kernelID,
            detail: "基于内核 task 结构，极难篡改",
            status: .safe // 它是基准，永远是“对”的
        ))
        
        // --- 6. 描述文件指纹 (Provisioning Profile) ---
        // 修复了之前的红色 BUG，增加了 TeamID 处理
        let provID = getMobileProvisionID()
        let (status, detail) = analyzeProvisionID(provID: provID, standard: cleanKernelID)
        items.append(ResultItem(
            method: "6. [证书层] mobileprovision",
            value: provID,
            detail: detail,
            status: status
        ))
        
        // --- 7. Runtime 完整性检测 (高级) ---
        // 检测 [NSBundle bundleIdentifier] 方法是否被篡改了地址
        let (runtimeStatus, runtimeMsg) = checkRuntimeIntegrity()
        items.append(ResultItem(
            method: "7. [Runtime] 方法地址完整性",
            value: runtimeStatus ? "未发现 Hook" : "⚠️ 检测到 Hook",
            detail: runtimeMsg,
            status: runtimeStatus ? .safe : .suspicious
        ))

        self.results = items
    }
    
    // --------------------------------------------------------------------
    // 辅助函数
    // --------------------------------------------------------------------
    
    // 剥离 TeamID (例如 "A1B2C3D4.com.test" -> "com.test")
    func stripTeamID(_ fullID: String) -> String {
        let components = fullID.components(separatedBy: ".")
        // 简单的启发式：如果第一段是10位大写字母数字混合，且后面还有内容，可能是 TeamID
        if components.count > 1 && components[0].count == 10 {
            return components.dropFirst().joined(separator: ".")
        }
        return fullID
    }
    
    func analyzeProvisionID(provID: String, standard: String) -> (Status, String) {
        if provID == "未找到 (可能是模拟器)" || provID.contains("读取错误") {
            return (.warning, "无法验证签名文件")
        }
        
        // 1. 完全匹配
        if provID == standard { return (.safe, "ID 完全一致") }
        
        // 2. 包含匹配 (处理 TeamID)
        if provID.hasSuffix("." + standard) {
            return (.safe, "匹配 (含 TeamID 前缀)")
        }
        
        // 3. 通配符证书 (企业签/个人签常用)
        if provID.contains("*") {
            return (.warning, "通配符证书 (Wildcard)")
        }
        
        return (.suspicious, "证书 ID 与运行 ID 不符")
    }

    // --- 实现 2: CFBundleGetIdentifier ---
    func getCFBundleIdentifier() -> String {
        let mainBundle = CFBundleGetMainBundle()
        if let idRef = CFBundleGetIdentifier(mainBundle) {
            return idRef as String
        }
        return "CF 获取失败"
    }

    // --- 实现 3: NSDictionary ---
    func getDictFromInfo() -> String {
        if let path = Bundle.main.path(forResource: "Info", ofType: "plist"),
           let dict = NSDictionary(contentsOfFile: path),
           let id = dict["CFBundleIdentifier"] as? String {
            return id
        }
        return "读取失败"
    }

    // --- 实现 4: fopen ---
    func getBundleIDFromPlistUsingFopen() -> String {
        guard let path = Bundle.main.path(forResource: "Info", ofType: "plist") else { return "No Info.plist" }
        guard let file = fopen(path, "r") else { return "fopen error" }
        defer { fclose(file) }
        fseek(file, 0, SEEK_END)
        let size = ftell(file)
        fseek(file, 0, SEEK_SET)
        if size <= 0 { return "Empty File" }
        var buffer = [CChar](repeating: 0, count: Int(size) + 1)
        fread(&buffer, 1, Int(size), file)
        let content = String(cString: buffer)
        
        // 简单 XML 解析
        if let range = content.range(of: "CFBundleIdentifier") {
            let sub = content[range.upperBound...]
            if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                return String(sub[start.upperBound..<end.lowerBound])
            }
        }
        return "Parse Fail"
    }

    // --- 实现 5: SecTask ---
    func getSecTaskSigningIdentifier() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else { return "SecTask Fail" }
        if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
            return idRef as String
        }
        return "Unknown"
    }
    
    // --- 实现 6: Provision ---
    func getMobileProvisionID() -> String {
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return "未找到 (可能是模拟器)"
        }
        do {
            // 使用 Latin1 尽可能保留二进制中的 ASCII 字符
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let content = String(data: data, encoding: .isoLatin1) ?? ""
            if let range = content.range(of: "<key>application-identifier</key>") {
                let sub = content[range.upperBound...]
                if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                    return String(sub[start.upperBound..<end.lowerBound])
                }
            }
        } catch { return "读取错误" }
        return "解析失败"
    }
    
    // --- 实现 7: Runtime 检测 (最强反 Hook) ---
    func checkRuntimeIntegrity() -> (Bool, String) {
        // 获取 NSBundle 类的 bundleIdentifier 方法的实现地址 (IMP)
        let selector = #selector(getter: Bundle.bundleIdentifier)
        guard let method = class_getInstanceMethod(Bundle.self, selector) else {
            return (false, "找不到方法")
        }
        let imp = method_getImplementation(method)
        
        // 使用 dladdr 查询该地址属于哪个镜像(Image)
        var info = Dl_info()
        if dladdr(UnsafeRawPointer(imp), &info) != 0 {
            let fname = String(cString: info.dli_fname)
            
            // 正常的 NSBundle 应该位于 CoreFoundation 或 Foundation 库中
            // 路径通常包含 /System/Library/Frameworks/CoreFoundation.framework/...
            if fname.contains("CoreFoundation") || fname.contains("Foundation") {
                return (true, "IMP 指向系统库")
            } else {
                // 如果指向了 CydiaSubstrate, Substitute, 或 App 自己的二进制，说明被 Hook 了
                return (false, "IMP 指向异常库: \(URL(fileURLWithPath: fname).lastPathComponent)")
            }
        }
        return (false, "无法获取 IMP 信息")
    }
}
