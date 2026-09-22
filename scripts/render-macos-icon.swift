import AppKit

let source = CommandLine.arguments[1]
let destination = CommandLine.arguments[2]
guard let image = NSImage(contentsOfFile: source),
      let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 1024, pixelsHigh: 1024,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
      let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
    fatalError("Unable to read the SVG icon or allocate its image")
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
NSColor.clear.setFill()
NSRect(x: 0, y: 0, width: 1024, height: 1024).fill(using: .copy)
image.draw(in: NSRect(x: 0, y: 0, width: 1024, height: 1024))
NSGraphicsContext.restoreGraphicsState()
guard [(0, 0), (1023, 0), (0, 1023), (1023, 1023)].allSatisfy({ x, y in
    bitmap.colorAt(x: x, y: y)?.alphaComponent == 0
}) else {
    fatalError("The icon must have transparent corners")
}
guard let png = bitmap.representation(using: .png, properties: [:]) else {
    fatalError("Unable to encode the icon")
}
try png.write(to: URL(fileURLWithPath: destination))
print("Rendered 1024x1024 PNG")
