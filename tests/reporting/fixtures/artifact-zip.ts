// Sanitized offline ZIP fixture writer, never used by production intake.
import { deflateRawSync, crc32 } from 'node:zlib'
export function zip(entries: Array<{ name: string; bytes?: Buffer; mode?: number; method?: number; crc?: number; size?: number; flags?: number }>) {
  const local: Buffer[] = [], central: Buffer[] = []; let offset = 0
  for (const e of entries) {
    const name = Buffer.from(e.name), bytes = e.bytes ?? Buffer.alloc(0), method = e.method ?? 0
    const compressed = method === 8 ? deflateRawSync(bytes) : bytes
    const header = Buffer.alloc(30); header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4); header.writeUInt16LE(e.flags ?? 0, 6); header.writeUInt16LE(method, 8)
    header.writeUInt32LE(e.crc ?? crc32(bytes), 14); header.writeUInt32LE(compressed.length, 18); header.writeUInt32LE(e.size ?? bytes.length, 22); header.writeUInt16LE(name.length, 26)
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50); c.writeUInt16LE(0x0314, 4); header.copy(c, 6, 4, 30); c.writeUInt32LE(((e.mode ?? 0o100644) * 65536) >>> 0, 38); c.writeUInt32LE(offset, 42)
    local.push(header, name, compressed); central.push(c, name); offset += header.length + name.length + compressed.length
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16)
  return Buffer.concat([...local, directory, end])
}
