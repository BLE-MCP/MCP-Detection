// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "swift_ast_analyzer",
    products: [
        .executable(name: "swift_ast_analyzer", targets: ["swift_ast_analyzer"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-syntax.git", from: "509.0.0"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.0.0")
    ],
    targets: [
        .executableTarget(
            name: "swift_ast_analyzer",
            dependencies: [
                .product(name: "SwiftSyntax", package: "swift-syntax"),
                .product(name: "SwiftParser", package: "swift-syntax"),
                .product(name: "Yams", package: "Yams")
            ],
            path: "Sources/swift_ast_analyzer"
        )
    ],
    swiftLanguageVersions: [.v5]
)
