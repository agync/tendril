import CTendril
import Dispatch
import Foundation
#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Security
#endif
#if canImport(NetworkExtension) && (os(iOS) || os(visionOS))
import NetworkExtension
#endif
import Testing
@testable import Tendril

private func onDedicatedTestThread(_ body: @escaping @Sendable () -> Void) {
  Thread(block: body).start()
}

private final class AtomicBox<T>: @unchecked Sendable {
  private let lock = NSLock()
  private var value: T

  init(_ value: T) {
    self.value = value
  }

  func set(_ next: T) {
    lock.lock()
    defer { lock.unlock() }
    value = next
  }

  func get() -> T {
    lock.lock()
    defer { lock.unlock() }
    return value
  }

  @discardableResult
  func modify<R>(_ body: (inout T) -> R) -> R {
    lock.lock()
    defer { lock.unlock() }
    return body(&value)
  }
}

// MARK: - Test-only pure-Swift FIPS 204 ML-DSA-65 signer for pre-OS-26 SDK verification

private enum TestKeccak {
  private static let roundConstants: [UInt64] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
  ]

  private static let rotOffsets: [Int] = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
  ]

  private static func rotl(_ x: UInt64, _ r: Int) -> UInt64 {
    r == 0 ? x : ((x << r) | (x >> (64 - r)))
  }

  private static func keccakF1600(_ state: inout [UInt64]) {
    var b = [UInt64](repeating: 0, count: 25)
    var c = [UInt64](repeating: 0, count: 5)
    var d = [UInt64](repeating: 0, count: 5)
    for round in 0..<24 {
      for x in 0..<5 {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
      }
      for x in 0..<5 {
        d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
      }
      for y in 0..<5 {
        for x in 0..<5 {
          state[x + 5 * y] ^= d[x]
        }
      }
      for y in 0..<5 {
        for x in 0..<5 {
          let idx = x + 5 * y
          let nx = y
          let ny = (2 * x + 3 * y) % 5
          b[nx + 5 * ny] = rotl(state[idx], rotOffsets[idx])
        }
      }
      for y in 0..<5 {
        let base = 5 * y
        for x in 0..<5 {
          state[base + x] = b[base + x] ^ ((~b[base + ((x + 1) % 5)]) & b[base + ((x + 2) % 5)])
        }
      }
      state[0] ^= roundConstants[round]
    }
  }

  static func shake(_ input: Data, rateBytes: Int, outLen: Int) -> Data {
    var state = [UInt64](repeating: 0, count: 25)
    var padded = Array(input)
    padded.append(0x1F)
    while padded.count % rateBytes != 0 {
      padded.append(0)
    }
    padded[padded.count - 1] ^= 0x80

    var offset = 0
    while offset < padded.count {
      for i in 0..<(rateBytes / 8) {
        var word: UInt64 = 0
        for b in 0..<8 {
          word |= UInt64(padded[offset + i * 8 + b]) << (b * 8)
        }
        state[i] ^= word
      }
      keccakF1600(&state)
      offset += rateBytes
    }

    var out = Data()
    out.reserveCapacity(outLen)
    while out.count < outLen {
      for i in 0..<(rateBytes / 8) {
        var w = state[i]
        for _ in 0..<8 {
          if out.count == outLen { break }
          out.append(UInt8(w & 0xFF))
          w >>= 8
        }
      }
      if out.count < outLen {
        keccakF1600(&state)
      }
    }
    return out
  }

  static func shake128(_ data: Data, outLen: Int) -> Data {
    shake(data, rateBytes: 168, outLen: outLen)
  }

  static func shake256(_ data: Data, outLen: Int) -> Data {
    shake(data, rateBytes: 136, outLen: outLen)
  }
}

private final class TestMlDsa65SoftwareKey: TendrilMlDsa65Provider, @unchecked Sendable {
  private static let q: Int64 = 8_380_417
  private static let n = 256
  private static let k = 6
  private static let l = 5
  private static let eta: Int64 = 4
  private static let d = 13
  private static let tau = 49
  private static let beta: Int64 = 196
  private static let gamma1: Int64 = 1 << 19
  private static let gamma2: Int64 = (8_380_417 - 1) / 32
  private static let omega = 55
  private static let ctildeBytes = 48

  private static let zetas: [Int32] = {
    func powMod(_ base: Int64, _ exp: Int, _ mod: Int64) -> Int32 {
      var res: Int64 = 1
      var b = base % mod
      var e = exp
      while e > 0 {
        if (e & 1) != 0 { res = (res * b) % mod }
        b = (b * b) % mod
        e >>= 1
      }
      return Int32(res)
    }
    var table = [Int32](repeating: 0, count: 256)
    for k in 1..<256 {
      var br = 0
      for bit in 0..<8 {
        if ((k >> bit) & 1) != 0 { br |= 1 << (7 - bit) }
      }
      table[k] = powMod(1753, br, q)
    }
    return table
  }()

  private let lock = NSLock()
  private let rho: Data
  private let kSeed: Data
  private let tr: Data
  private let s1Hat: [[Int32]]
  private let s2Hat: [[Int32]]
  private let t0Hat: [[Int32]]
  private let aHat: [[[Int32]]]
  private var signCallsCount = 0

  let publicKeyData: Data

  var signCalls: Int {
    lock.lock()
    defer { lock.unlock() }
    return signCallsCount
  }

  init(seed: Data) {
    precondition(seed.count == 32)
    var seedInput = Data(seed)
    seedInput.append(contentsOf: [UInt8(Self.k), UInt8(Self.l)])
    let expanded = TestKeccak.shake256(seedInput, outLen: 128)
    let rho = Data(expanded[0..<32])
    let rhoPrime = Data(expanded[32..<96])
    let kSeed = Data(expanded[96..<128])
    let aHat = Self.expandA(rho)
    let s1 = (0..<Self.l).map { Self.rejBoundedPoly(rhoPrime, nonce: UInt16($0)) }
    let s2 = (0..<Self.k).map { Self.rejBoundedPoly(rhoPrime, nonce: UInt16(Self.l + $0)) }
    let s1Hat = s1.map { Self.ntt($0) }
    var t: [[Int32]] = []
    for i in 0..<Self.k {
      var acc = [Int32](repeating: 0, count: Self.n)
      for j in 0..<Self.l {
        acc = Self.addPoly(acc, Self.mulNtt(aHat[i][j], s1Hat[j]))
      }
      t.append(Self.addPoly(Self.invNtt(acc), s2[i]))
    }
    var t1: [[Int32]] = []
    var t0: [[Int32]] = []
    for poly in t {
      var p1 = [Int32](repeating: 0, count: Self.n)
      var p0 = [Int32](repeating: 0, count: Self.n)
      for idx in 0..<Self.n {
        let (hi, lo) = Self.power2Round(poly[idx])
        p1[idx] = hi
        p0[idx] = lo
      }
      t1.append(p1)
      t0.append(p0)
    }
    let pk = Self.pkEncode(rho: rho, t1: t1)
    let tr = TestKeccak.shake256(pk, outLen: 64)

    self.rho = rho
    self.kSeed = kSeed
    self.tr = tr
    self.aHat = aHat
    self.s1Hat = s1Hat
    self.s2Hat = s2.map { Self.ntt($0) }
    self.t0Hat = t0.map { Self.ntt($0) }
    self.publicKeyData = pk
  }

  func sign(message: Data, context: Data) throws -> Data {
    lock.lock()
    signCallsCount += 1
    lock.unlock()

    guard context.count <= 255 else {
      throw TendrilMlDsa65Error.signingFailed("context exceeds 255 bytes")
    }
    var mPrime = Data([0, UInt8(context.count)])
    mPrime.append(context)
    mPrime.append(message)

    var trMsg = Data(tr)
    trMsg.append(mPrime)
    let mu = TestKeccak.shake256(trMsg, outLen: 64)

    var rppInput = Data(kSeed)
    rppInput.append(Data(count: 32))
    rppInput.append(mu)
    let rhoPrimePrime = TestKeccak.shake256(rppInput, outLen: 64)

    var kappa = 0
    while true {
      let y = Self.expandMask(rhoPrimePrime, mu: kappa)
      kappa += Self.l
      let yHat = y.map { Self.ntt($0) }
      var w: [[Int32]] = []
      for i in 0..<Self.k {
        var acc = [Int32](repeating: 0, count: Self.n)
        for j in 0..<Self.l {
          acc = Self.addPoly(acc, Self.mulNtt(aHat[i][j], yHat[j]))
        }
        w.append(Self.invNtt(acc))
      }
      let w1 = w.map { poly in poly.map { Self.decompose($0).0 } }
      var cInput = Data(mu)
      cInput.append(Self.w1Encode(w1))
      let cTilde = TestKeccak.shake256(cInput, outLen: Self.ctildeBytes)
      let c = Self.sampleInBall(cTilde)
      let cHat = Self.ntt(c)

      let cs1 = (0..<Self.l).map { Self.invNtt(Self.mulNtt(cHat, s1Hat[$0])) }
      let cs2 = (0..<Self.k).map { Self.invNtt(Self.mulNtt(cHat, s2Hat[$0])) }
      let z = (0..<Self.l).map { Self.addPoly(y[$0], cs1[$0]) }
      if Self.infNorm(z) >= Self.gamma1 - Self.beta {
        continue
      }
      var r0Exceeds = false
      for i in 0..<Self.k {
        let diff = Self.subPoly(w[i], cs2[i])
        for coeff in diff {
          if abs(Self.decompose(coeff).1) >= Self.gamma2 - Self.beta {
            r0Exceeds = true
            break
          }
        }
        if r0Exceeds { break }
      }
      if r0Exceeds {
        continue
      }

      let ct0 = (0..<Self.k).map { Self.invNtt(Self.mulNtt(cHat, t0Hat[$0])) }
      if Self.infNorm(ct0) >= Self.gamma2 {
        continue
      }

      var h: [[Int32]] = []
      var hintOnes = 0
      for i in 0..<Self.k {
        let wMinusCs2PlusCt0 = Self.addPoly(Self.subPoly(w[i], cs2[i]), ct0[i])
        var row = [Int32](repeating: 0, count: Self.n)
        for idx in 0..<Self.n {
          let negCt0 = Self.modQ(-Int64(ct0[i][idx]))
          let bit = Self.makeHint(z: negCt0, r: wMinusCs2PlusCt0[idx])
          row[idx] = bit
          hintOnes += Int(bit)
        }
        h.append(row)
      }
      if hintOnes > Self.omega {
        continue
      }
      return Self.sigEncode(cTilde: cTilde, z: z, h: h)
    }
  }

  private static func modQ(_ x: Int64) -> Int32 {
    let r = x % q
    return Int32(r >= 0 ? r : r + q)
  }

  private static func center(_ r: Int32) -> Int64 {
    let v = Int64(modQ(Int64(r)))
    return v > (q - 1) / 2 ? v - q : v
  }

  private static func ntt(_ a: [Int32]) -> [Int32] {
    var w = a
    var kIdx = 0
    var len = 128
    while len >= 1 {
      var start = 0
      while start < 256 {
        kIdx += 1
        let z = Int64(zetas[kIdx])
        for j in start..<(start + len) {
          let t = Int64(modQ(z * Int64(w[j + len])))
          w[j + len] = modQ(Int64(w[j]) - t)
          w[j] = modQ(Int64(w[j]) + t)
        }
        start += 2 * len
      }
      len >>= 1
    }
    return w
  }

  private static func invNtt(_ a: [Int32]) -> [Int32] {
    var w = a
    var kIdx = 256
    var len = 1
    while len < 256 {
      var start = 0
      while start < 256 {
        kIdx -= 1
        let z = -Int64(zetas[kIdx])
        for j in start..<(start + len) {
          let t = Int64(w[j])
          let u = Int64(w[j + len])
          w[j] = modQ(t + u)
          w[j + len] = modQ(z * (t - u))
        }
        start += 2 * len
      }
      len <<= 1
    }
    let f: Int64 = 8_347_681
    return w.map { modQ(Int64($0) * f) }
  }

  private static func addPoly(_ a: [Int32], _ b: [Int32]) -> [Int32] {
    (0..<n).map { modQ(Int64(a[$0]) + Int64(b[$0])) }
  }

  private static func subPoly(_ a: [Int32], _ b: [Int32]) -> [Int32] {
    (0..<n).map { modQ(Int64(a[$0]) - Int64(b[$0])) }
  }

  private static func mulNtt(_ a: [Int32], _ b: [Int32]) -> [Int32] {
    (0..<n).map { modQ(Int64(a[$0]) * Int64(b[$0])) }
  }

  private static func power2Round(_ r: Int32) -> (Int32, Int32) {
    let rv = Int64(modQ(Int64(r)))
    let twoD: Int64 = 1 << d
    var r0 = rv % twoD
    if r0 > (twoD >> 1) {
      r0 -= twoD
    }
    return (Int32((rv - r0) >> d), Int32(r0))
  }

  private static func decompose(_ r: Int32) -> (Int32, Int64) {
    let rv = Int64(modQ(Int64(r)))
    let step = 2 * gamma2
    var r0 = rv % step
    if r0 > gamma2 {
      r0 -= step
    }
    var r1: Int64
    if rv - r0 == q - 1 {
      r1 = 0
      r0 -= 1
    } else {
      r1 = (rv - r0) / step
    }
    return (Int32(r1), r0)
  }

  private static func makeHint(z: Int32, r: Int32) -> Int32 {
    let r1 = decompose(r).0
    let v1 = decompose(modQ(Int64(r) + Int64(z))).0
    return r1 != v1 ? 1 : 0
  }

  private static func infNorm(_ vec: [[Int32]]) -> Int64 {
    var mx: Int64 = 0
    for p in vec {
      for c in p {
        let a = abs(center(c))
        if a > mx { mx = a }
      }
    }
    return mx
  }

  private static func expandA(_ rho: Data) -> [[[Int32]]] {
    var mat: [[[Int32]]] = []
    for r in 0..<k {
      var row: [[Int32]] = []
      for s in 0..<l {
        var seed = Data(rho)
        seed.append(contentsOf: [UInt8(s), UInt8(r)])
        var streamLen = 840
        var xof = Array(TestKeccak.shake128(seed, outLen: streamLen))
        var coeffs: [Int32] = []
        var idx = 0
        while coeffs.count < n {
          if idx + 3 > xof.count {
            streamLen += 256
            xof = Array(TestKeccak.shake128(seed, outLen: streamLen))
          }
          let b0 = Int32(xof[idx])
          let b1 = Int32(xof[idx + 1])
          let b2 = Int32(xof[idx + 2] & 0x7F)
          idx += 3
          let val = b0 | (b1 << 8) | (b2 << 16)
          if val < Int32(q) {
            coeffs.append(val)
          }
        }
        row.append(coeffs)
      }
      mat.append(row)
    }
    return mat
  }

  private static func rejBoundedPoly(_ rhoPrime: Data, nonce: UInt16) -> [Int32] {
    var seed = Data(rhoPrime)
    seed.append(UInt8(nonce & 0xFF))
    seed.append(UInt8(nonce >> 8))
    var streamLen = 512
    var xof = Array(TestKeccak.shake256(seed, outLen: streamLen))
    var coeffs: [Int32] = []
    var idx = 0
    while coeffs.count < n {
      if idx >= xof.count {
        streamLen += 256
        xof = Array(TestKeccak.shake256(seed, outLen: streamLen))
      }
      let b = xof[idx]
      idx += 1
      let z0 = b & 0x0F
      let z1 = b >> 4
      if z0 < 9 {
        coeffs.append(modQ(eta - Int64(z0)))
      }
      if z1 < 9 && coeffs.count < n {
        coeffs.append(modQ(eta - Int64(z1)))
      }
    }
    return coeffs
  }

  private static func expandMask(_ rhoPrime: Data, mu: Int) -> [[Int32]] {
    var vec: [[Int32]] = []
    for r in 0..<l {
      let idxVal = UInt16(mu + r)
      var seed = Data(rhoPrime)
      seed.append(UInt8(idxVal & 0xFF))
      seed.append(UInt8(idxVal >> 8))
      let bytes = Array(TestKeccak.shake256(seed, outLen: 640))
      var coeffs: [Int32] = []
      coeffs.reserveCapacity(n)
      var i = 0
      while i < 640 {
        let x: UInt64 = UInt64(bytes[i])
          | (UInt64(bytes[i + 1]) << 8)
          | (UInt64(bytes[i + 2]) << 16)
          | (UInt64(bytes[i + 3]) << 24)
          | (UInt64(bytes[i + 4]) << 32)
        let c0 = Int64(x & 0xF_FFFF)
        let c1 = Int64((x >> 20) & 0xF_FFFF)
        coeffs.append(modQ(gamma1 - c0))
        coeffs.append(modQ(gamma1 - c1))
        i += 5
      }
      vec.append(coeffs)
    }
    return vec
  }

  private static func sampleInBall(_ cTilde: Data) -> [Int32] {
    var streamLen = 256
    var xof = Array(TestKeccak.shake256(cTilde, outLen: streamLen))
    var h: UInt64 = 0
    for i in 0..<8 {
      h |= UInt64(xof[i]) << (i * 8)
    }
    var c = [Int32](repeating: 0, count: n)
    var idx = 8
    for i in (n - tau)..<n {
      var j = 256
      while true {
        if idx >= xof.count {
          streamLen += 128
          xof = Array(TestKeccak.shake256(cTilde, outLen: streamLen))
        }
        j = Int(xof[idx])
        idx += 1
        if j <= i { break }
      }
      c[i] = c[j]
      c[j] = ((h & 1) != 0) ? Int32(q - 1) : 1
      h >>= 1
    }
    return c
  }

  private static func packBits(_ vals: [UInt64], bits: Int) -> Data {
    var acc: UInt64 = 0
    var nbits = 0
    var out = Data()
    let mask: UInt64 = (1 << bits) - 1
    for v in vals {
      acc |= (v & mask) << nbits
      nbits += bits
      while nbits >= 8 {
        out.append(UInt8(acc & 0xFF))
        acc >>= 8
        nbits -= 8
      }
    }
    if nbits > 0 {
      out.append(UInt8(acc & 0xFF))
    }
    return out
  }

  private static func pkEncode(rho: Data, t1: [[Int32]]) -> Data {
    var out = Data(rho)
    for p in t1 {
      out.append(packBits(p.map { UInt64($0) }, bits: 10))
    }
    return out
  }

  private static func w1Encode(_ w1: [[Int32]]) -> Data {
    var out = Data()
    for p in w1 {
      out.append(packBits(p.map { UInt64($0) }, bits: 4))
    }
    return out
  }

  private static func sigEncode(cTilde: Data, z: [[Int32]], h: [[Int32]]) -> Data {
    var out = Data(cTilde)
    for p in z {
      let vals = p.map { UInt64(gamma1 - center($0)) }
      out.append(packBits(vals, bits: 20))
    }
    var hintBuf = [UInt8](repeating: 0, count: omega + k)
    var idx = 0
    for i in 0..<k {
      for j in 0..<n where h[i][j] != 0 {
        hintBuf[idx] = UInt8(j)
        idx += 1
      }
      hintBuf[omega + i] = UInt8(idx)
    }
    out.append(contentsOf: hintBuf)
    return out
  }
}

private final class BadLengthMlDsa65Provider: TendrilMlDsa65Provider, @unchecked Sendable {
  let publicKeyData: Data

  init(length: Int) {
    self.publicKeyData = Data(repeating: 0xAA, count: length)
  }

  func sign(message: Data, context: Data) throws -> Data {
    Data(repeating: 0, count: Int(TENDRIL_MLDSA65_SIG_LEN))
  }
}

@Suite
struct AppleCustodyAndBackgroundTests {
  private func hexToData(_ hex: String) -> Data {
    var out = Data(capacity: hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
      let next = hex.index(idx, offsetBy: 2)
      out.append(UInt8(hex[idx..<next], radix: 16)!)
      idx = next
    }
    return out
  }

  private func vectorsDir() -> URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("spec")
      .appendingPathComponent("vectors")
  }

  private func jsonObj(_ json: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
  }

  @Test
  func testDoubleMlDsa65PubkeyMatchesConformanceVector() throws {
    let data = try Data(contentsOf: vectorsDir().appendingPathComponent("grants.json"))
    let gv = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    let seed = hexToData(gv["root_signing_mldsa_seed_hex"] as! String)
    let fullPub = hexToData(gv["root_signing_pub_hex"] as! String)
    let signer = TestMlDsa65SoftwareKey(seed: seed)
    #expect(signer.publicKeyData.count == Int(TENDRIL_MLDSA65_PUB_LEN))
    #expect(signer.publicKeyData == Data(fullPub.dropFirst(32)))
  }

  @Test
  func cBridgeOwnershipDropsOnceOnFailureAndWaitsForLiveSession() throws {
    let fm = FileManager.default
    let baseDir = fm.temporaryDirectory.appendingPathComponent("tendril-bridge-own-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: baseDir) }
    try fm.createDirectory(at: baseDir, withIntermediateDirectories: true)

    let signer = TestMlDsa65SoftwareKey(seed: Data(repeating: 0x31, count: 32))

    // 1. Wrong public key length throws before retaining -> zero drop callbacks.
    let badLen = BadLengthMlDsa65Provider(length: Int(TENDRIL_MLDSA65_PUB_LEN) - 1)
    let badDrops = AtomicBox(0)
    let badBridge = CTendrilMlDsa65Bridge(provider: badLen) {
      badDrops.modify { $0 += 1 }
    }
    #expect(throws: TendrilMlDsa65Error.invalidPublicKeyLength(Int(TENDRIL_MLDSA65_PUB_LEN) - 1)) {
      _ = try badBridge.withCSigner { _, _ in Optional<OpaquePointer>.none }
    }
    #expect(badDrops.get() == 0)

    // 2. C failure (invalid options JSON returning nil) must run drop_ctx exactly once inside Rust.
    let errDrops = AtomicBox(0)
    let errBridge = CTendrilMlDsa65Bridge(provider: signer) {
      errDrops.modify { $0 += 1 }
    }
    let nilPtr: OpaquePointer? = try errBridge.withCSigner { cSignerPtr, markTransferred in
      baseDir.path.withCString { cDir -> OpaquePointer? in
        "{\"unknown_opt\":true}".withCString { cOpts -> OpaquePointer? in
          markTransferred()
          return tendril_endpoint_new_sealed_with_options(cDir, nil, nil, nil, cOpts, cSignerPtr)
        }
      }
    }
    #expect(nilPtr == nil)
    #expect(errDrops.get() == 1)

    // 2B. Throwing inside body after markTransferred() must not double-release ctx in defer.
    let postThrowDrops = AtomicBox(0)
    let postThrowBridge = CTendrilMlDsa65Bridge(provider: signer) {
      postThrowDrops.modify { $0 += 1 }
    }
    let postThrowDir = baseDir.appendingPathComponent("post-throw")
    try fm.createDirectory(at: postThrowDir, withIntermediateDirectories: true)
    var leakedPtrForCleanup: OpaquePointer?
    #expect(throws: TendrilError.invalidArgument("post-transfer")) {
      _ = try postThrowBridge.withCSigner { cSignerPtr, markTransferred -> OpaquePointer? in
        let ptr: OpaquePointer? = postThrowDir.path.withCString { cDir -> OpaquePointer? in
          markTransferred()
          return tendril_endpoint_new_sealed_with_options(cDir, nil, nil, "post-throw-host", nil, cSignerPtr)
        }
        leakedPtrForCleanup = ptr
        throw TendrilError.invalidArgument("post-transfer")
      }
    }
    #expect(postThrowDrops.get() == 0)
    if let leakedPtrForCleanup {
      tendril_endpoint_free(leakedPtrForCleanup)
    }
    #expect(postThrowDrops.get() == 1)

    // 3A. Without an active TendrilGroup, Rust TendrilSession does not hold Arc<EndpointIdentity>,
    // so freeing the endpoint invokes drop_ctx once while the live session keeps exchanging data.
    let hostDropsA = AtomicBox(0)
    let hostBridgeA = CTendrilMlDsa65Bridge(provider: signer) {
      hostDropsA.modify { $0 += 1 }
    }
    let hostDirA = baseDir.appendingPathComponent("host-no-grp")
    try fm.createDirectory(at: hostDirA, withIntermediateDirectories: true)
    let hostPtrA: OpaquePointer? = try hostBridgeA.withCSigner { cSignerPtr, markTransferred in
      hostDirA.path.withCString { cDir -> OpaquePointer? in
        "bridge-host-a".withCString { cHost -> OpaquePointer? in
          markTransferred()
          return tendril_endpoint_new_sealed_with_options(cDir, nil, nil, cHost, nil, cSignerPtr)
        }
      }
    }
    let unwrappedHostPtrA = try #require(hostPtrA)
    #expect(hostDropsA.get() == 0)

    let clientEp = try TendrilEndpoint(hostId: "bridge-cli")
    defer { clientEp.close() }

    func pairAndOpenSession(
      hostPtr: OpaquePointer,
      expectedHostId: String
    ) throws -> (cliSess: TendrilSession, hostSess: OpaquePointer, cliDevId: String, sas: String) {
      var epOut: UnsafeMutablePointer<CChar>?
      #expect(
        "127.0.0.1:0".withCString { cAddr in
          tendril_endpoint_serve_direct(hostPtr, cAddr, &epOut)
        } == TENDRIL_OK.rawValue
      )
      let listenEp = String(cString: try #require(epOut))
      tendril_string_free(epOut)

      var codeOut: UnsafeMutablePointer<CChar>?
      #expect(
        "lan".withCString { cKind in
          tendril_endpoint_issue_code(hostPtr, cKind, &codeOut)
        } == TENDRIL_OK.rawValue
      )
      let code = String(cString: try #require(codeOut))
      tendril_string_free(codeOut)

      let hostAddrInt = UInt(bitPattern: hostPtr)
      let pairSem = DispatchSemaphore(value: 0)
      let accBox = AtomicBox<String?>(nil)
      onDedicatedTestThread {
        let ptr = OpaquePointer(bitPattern: hostAddrInt)!
        var out: UnsafeMutablePointer<CChar>?
        if tendril_endpoint_pair_v2_accept(ptr, 5_000, &out) == TENDRIL_OK.rawValue, let out {
          accBox.set(String(cString: out))
          tendril_string_free(out)
        }
        pairSem.signal()
      }

      let pairInitJson = try clientEp.pairV2Initiate(endpoint: listenEp, code: code, deviceName: "cli")
      #expect(pairSem.wait(timeout: .now() + 5.0) == .success)
      let accObj = try jsonObj(try #require(accBox.get()))
      let initObj = try jsonObj(pairInitJson)
      let sas = try #require(initObj["sas"] as? String)
      let cliDevId = try #require(accObj["device_id"] as? String)

      #expect(
        cliDevId.withCString { cPeer in
          sas.withCString { cSas in
            tendril_endpoint_confirm_peer(hostPtr, cPeer, cSas)
          }
        } == TENDRIL_OK.rawValue
      )
      try clientEp.confirmPeer(peerId: expectedHostId, sas: sas)

      var grantOut: UnsafeMutablePointer<CChar>?
      #expect(
        cliDevId.withCString { cPeer in
          "[\"fs.read\"]".withCString { cCaps in
            tendril_endpoint_mint_grant(hostPtr, cPeer, cCaps, 300, &grantOut)
          }
        } == TENDRIL_OK.rawValue
      )
      let grantJson = String(cString: try #require(grantOut))
      tendril_string_free(grantOut)

      let sessSem = DispatchSemaphore(value: 0)
      let hostSessBox = AtomicBox<UInt>(0)
      onDedicatedTestThread {
        let ptr = OpaquePointer(bitPattern: hostAddrInt)!
        let sess = tendril_session_accept_v2(ptr, 5_000)
        hostSessBox.set(sess.map { UInt(bitPattern: $0) } ?? 0)
        sessSem.signal()
      }
      let cliSess = try clientEp.connectV2(
        endpoint: listenEp,
        targetHostId: expectedHostId,
        grantJson: grantJson
      )
      #expect(sessSem.wait(timeout: .now() + 5.0) == .success)
      let unwrappedHostSess = try #require(OpaquePointer(bitPattern: hostSessBox.get()))
      return (cliSess, unwrappedHostSess, cliDevId, sas)
    }

    let pairA = try pairAndOpenSession(hostPtr: unwrappedHostPtrA, expectedHostId: "bridge-host-a")
    #expect(hostDropsA.get() == 0)

    tendril_endpoint_free(unwrappedHostPtrA)
    #expect(hostDropsA.get() == 1)

    try pairA.cliSess.sendData(Data("after-ep-free-no-group".utf8))
    var evOutA: UnsafeMutablePointer<CChar>?
    #expect(tendril_session_poll_event(pairA.hostSess, 2_000, &evOutA) == TENDRIL_OK.rawValue)
    tendril_string_free(evOutA)
    tendril_session_free(pairA.hostSess)
    pairA.cliSess.free()

    // 3B. With an open TendrilGroup (GroupPool retains Arc<EndpointIdentity>), freeing the
    // endpoint and sessions keeps hostDropsB == 0 until the last group closes and frees.
    let hostDropsB = AtomicBox(0)
    let hostBridgeB = CTendrilMlDsa65Bridge(provider: signer) {
      hostDropsB.modify { $0 += 1 }
    }
    let hostDirB = baseDir.appendingPathComponent("host-with-grp")
    try fm.createDirectory(at: hostDirB, withIntermediateDirectories: true)
    let hostPtrB: OpaquePointer? = try hostBridgeB.withCSigner { cSignerPtr, markTransferred in
      hostDirB.path.withCString { cDir -> OpaquePointer? in
        markTransferred()
        return tendril_endpoint_new_sealed_with_options(cDir, nil, nil, nil, nil, cSignerPtr)
      }
    }
    let unwrappedHostPtrB = try #require(hostPtrB)
    var infoOutB: UnsafeMutablePointer<CChar>?
    #expect(tendril_endpoint_info_json(unwrappedHostPtrB, &infoOutB) == TENDRIL_OK.rawValue)
    let hostInfoB = try jsonObj(String(cString: try #require(infoOutB)))
    tendril_string_free(infoOutB)
    let hostBId = try #require(hostInfoB["host_id"] as? String)

    let pairB = try pairAndOpenSession(hostPtr: unwrappedHostPtrB, expectedHostId: hostBId)

    var manifestOut: UnsafeMutablePointer<CChar>?
    #expect(
      "bridge-grp".withCString { cName in
        tendril_group_create(unwrappedHostPtrB, cName, 2, nil, &manifestOut)
      } == TENDRIL_OK.rawValue
    )
    let manifestObj = try jsonObj(String(cString: try #require(manifestOut)))
    tendril_string_free(manifestOut)
    let groupId = try #require(manifestObj["group_id"] as? String)

    var groupOut: OpaquePointer?
    #expect(
      groupId.withCString { cGroup in
        tendril_group_open(unwrappedHostPtrB, cGroup, nil, &groupOut)
      } == TENDRIL_OK.rawValue
    )
    let unwrappedHostGroup = try #require(groupOut)

    tendril_endpoint_free(unwrappedHostPtrB)
    #expect(hostDropsB.get() == 0)

    try pairB.cliSess.sendData(Data("after-ep-free-with-group".utf8))
    var evOutB: UnsafeMutablePointer<CChar>?
    #expect(tendril_session_poll_event(pairB.hostSess, 2_000, &evOutB) == TENDRIL_OK.rawValue)
    tendril_string_free(evOutB)

    tendril_session_free(pairB.hostSess)
    pairB.cliSess.free()
    #expect(hostDropsB.get() == 0)

    #expect(tendril_group_close(unwrappedHostGroup) == TENDRIL_OK.rawValue)
    tendril_group_free(unwrappedHostGroup)
    #expect(hostDropsB.get() == 1)
  }

  @Test
  func extensionClientOnlyRefusesHostingAndAllowsOutbound() throws {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent("tendril-ext-cli-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: dir) }

    #if canImport(CryptoKit) && canImport(Security)
    let key = SymmetricKey(size: .bits256)
    let kc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "ext-\(UUID().uuidString)") {
      key
    }
    let ep = try TendrilEndpoint(
      stateDir: dir.path,
      hostId: "swift-ext-cli",
      keychainStore: kc,
      options: .extensionClientOnly
    )
    #else
    let ep = try TendrilEndpoint(
      stateDir: dir.path,
      hostId: "swift-ext-cli",
      options: .extensionClientOnly
    )
    #endif
    defer { ep.close() }

    func expectClientOnlyError(_ block: () throws -> Void) {
      do {
        try block()
        Issue.record("expected client_only failure")
      } catch TendrilError.ffi(let code, let message) {
        #expect(code == TENDRIL_ERR_INVALID_ARG.rawValue)
        #expect(message.contains("client_only"), "unexpected error: \(message)")
      } catch {
        Issue.record("unexpected error type: \(error)")
      }
    }

    expectClientOnlyError { _ = try ep.serveDirect(listenAddr: "127.0.0.1:0") }
    expectClientOnlyError { _ = try ep.serveRelay(relayUrl: "wss://relay.example/v1/relay") }
    expectClientOnlyError { _ = try ep.serveRelayV2(relayUrl: "wss://relay.example/v2/relay") }
    expectClientOnlyError { _ = try ep.serveP2p() }
    expectClientOnlyError { _ = try ep.issuePairingUri() }
    expectClientOnlyError { _ = try ep.refreshRoutes() }
    expectClientOnlyError { _ = try ep.openGroup(groupId: "grp-ext", listenAddr: "127.0.0.1:0") }

    // With explicit hostId != device_id, listenAddr: nil reaches the group identity invariant.
    do {
      _ = try ep.openGroup(groupId: "grp-ext", listenAddr: nil)
      Issue.record("expected protocol failure when host_id != device_id")
    } catch TendrilError.ffi(let code, let message) {
      #expect(code == TENDRIL_ERR_PROTOCOL.rawValue, "unexpected error: \(message)")
    }

    // With default hostId (host_id == device_id), listenAddr: nil reaches group lookup.
    let defaultDir = fm.temporaryDirectory.appendingPathComponent("tendril-ext-def-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: defaultDir) }
    #if canImport(CryptoKit) && canImport(Security)
    let defaultKey = SymmetricKey(size: .bits256)
    let defaultKc = TendrilKeychainStore(
      service: "dev.tendril.state.test",
      account: "ext-def-\(UUID().uuidString)"
    ) { defaultKey }
    let defaultEp = try TendrilEndpoint(
      stateDir: defaultDir.path,
      hostId: nil,
      keychainStore: defaultKc,
      options: .extensionClientOnly
    )
    #else
    let defaultEp = try TendrilEndpoint(
      stateDir: defaultDir.path,
      hostId: nil,
      options: .extensionClientOnly
    )
    #endif
    defer { defaultEp.close() }
    expectClientOnlyError { _ = try defaultEp.openGroup(groupId: "grp-ext", listenAddr: "127.0.0.1:0") }
    #expect(
      throws: TendrilError.ffi(
        code: TENDRIL_ERR_NOT_FOUND.rawValue,
        message: "core protocol error: group not found: grp-ext"
      )
    ) {
      _ = try defaultEp.openGroup(groupId: "grp-ext", listenAddr: nil)
    }

    // Outbound connection from extension endpoint succeeds.
    let host = try TendrilEndpoint(hostId: "swift-ext-host")
    defer { host.close() }
    let addr = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let code = try host.issueCode(kind: "lan")

    let sem = DispatchSemaphore(value: 0)
    let accBox = AtomicBox<String?>(nil)
    onDedicatedTestThread {
      accBox.set(try? host.pairV2Accept(timeoutMs: 5_000))
      sem.signal()
    }
    let initObj = try jsonObj(try ep.pairV2Initiate(endpoint: addr, code: code, deviceName: "nse"))
    #expect(sem.wait(timeout: .now() + 5.0) == .success)
    let accObj = try jsonObj(try #require(accBox.get()))
    let sas = try #require(initObj["sas"] as? String)
    let cliId = try #require(accObj["device_id"] as? String)
    try host.confirmPeer(peerId: cliId, sas: sas)
    try ep.confirmPeer(peerId: "swift-ext-host", sas: sas)
    let grant = try host.mintGrant(peerId: cliId, capsJson: "[\"fs.read\"]", ttlSecs: 300)

    let sessSem = DispatchSemaphore(value: 0)
    let srvBox = AtomicBox<TendrilSession?>(nil)
    onDedicatedTestThread {
      srvBox.set(try? host.acceptV2(timeoutMs: 5_000))
      sessSem.signal()
    }
    let cliSess = try ep.connectV2(endpoint: addr, targetHostId: "swift-ext-host", grantJson: grant)
    defer { cliSess.free() }
    #expect(sessSem.wait(timeout: .now() + 5.0) == .success)
    let srvSess = try #require(srvBox.get())
    defer { srvSess.free() }
    try cliSess.sendData(Data("ext-ok".utf8))
    let ev = try jsonObj(try srvSess.pollEvent(timeoutMs: 2_000))
    #expect(ev["event"] as? String == "data")
  }

  @Test
  func expiringActivityCoordinatorHandlesNormalMidFlightAndImmediateExpiry() throws {
    // 1. Normal completion returns value without invoking onExpire.
    let expiredCalls1 = AtomicBox(0)
    let normal = TendrilExpiringActivityState<Int> {
      expiredCalls1.modify { $0 += 1 }
    }
    normal.handleEvent(expired: false) { 42 }
    #expect(try normal.wait() == 42)
    #expect(expiredCalls1.get() == 0)

    // 2. Mid-flight expiration invokes onExpire once without double-signaling.
    let expiredCalls2 = AtomicBox(0)
    let entered = DispatchSemaphore(value: 0)
    let releaseBody = DispatchSemaphore(value: 0)
    let midFlight = TendrilExpiringActivityState<String> {
      expiredCalls2.modify { $0 += 1 }
      releaseBody.signal()
    }
    onDedicatedTestThread {
      midFlight.handleEvent(expired: false) {
        entered.signal()
        _ = releaseBody.wait(timeout: .now() + 5.0)
        return "unblocked"
      }
    }
    #expect(entered.wait(timeout: .now() + 5.0) == .success)
    midFlight.handleEvent(expired: true) { "ignored" }
    #expect(try midFlight.wait() == "unblocked")
    #expect(expiredCalls2.get() == 1)

    // 3. Immediate expiration before body runs skips body and fails closed with TendrilError.closed.
    let bodyRan = AtomicBox(false)
    let expiredCalls3 = AtomicBox(0)
    let immediate = TendrilExpiringActivityState<Int> {
      expiredCalls3.modify { $0 += 1 }
    }
    immediate.handleEvent(expired: true) {
      bodyRan.set(true)
      return 1
    }
    immediate.handleEvent(expired: false) {
      bodyRan.set(true)
      return 1
    }
    #expect(throws: TendrilError.closed) {
      _ = try immediate.wait()
    }
    #expect(!bodyRan.get())
    #expect(expiredCalls3.get() == 1)
  }

  @Test
  func wakePayloadParsingAndVerifyWakeTagWindow() throws {
    let secret = Data((0..<32).map { UInt8(0x20 + $0) })
    let nowUnix: UInt64 = 1_764_115_200

    #if canImport(CryptoKit) && canImport(Security)
    let epoch = nowUnix / 3600
    var salt = Data(count: 8)
    for i in 0..<8 {
      salt[i] = UInt8((epoch >> (56 - i * 8)) & 0xFF)
    }
    let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: secret), salt: salt)
    let tagKey = HKDF<SHA256>.expand(
      pseudoRandomKey: prk,
      info: Data("tendril/wake/epoch-tag/v1".utf8),
      outputByteCount: 16
    )
    let tagBytes = tagKey.withUnsafeBytes { Data($0) }
    let tagB64 = tagBytes.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")

    for delta in [-3600, 0, 3600] {
      let checkNow = UInt64(Int64(nowUnix) + Int64(delta))
      #expect(try TendrilCrypto.verifyWakeTag(secret: secret, tagB64: tagB64, nowUnixSecs: checkNow))
    }
    for delta in [-7200, 7200] {
      let checkNow = UInt64(Int64(nowUnix) + Int64(delta))
      #expect(!(try TendrilCrypto.verifyWakeTag(secret: secret, tagB64: tagB64, nowUnixSecs: checkNow)))
    }
    let wrongSecret = Data(repeating: 0xAA, count: 32)
    #expect(!(try TendrilCrypto.verifyWakeTag(secret: wrongSecret, tagB64: tagB64, nowUnixSecs: nowUnix)))

    let validUserInfo: [AnyHashable: Any] = [
      "aps": ["mutable-content": 1, "alert": ["loc-key": "TENDRIL_WAKE_FALLBACK"]],
      "v": 1,
      "wake_tag": tagB64,
      "epoch_s": (nowUnix / 3600) * 3600,
    ]
    let parsed = try TendrilWakePayload(userInfo: validUserInfo)
    #expect(parsed.v == 1)
    #expect(parsed.wakeTag == tagB64)
    #expect(parsed.epochS == 1_764_115_200)
    #endif

    #expect(throws: Error.self) {
      _ = try TendrilCrypto.verifyWakeTag(secret: Data(repeating: 1, count: 16), tagB64: "AAAAAAAAAAAAAAAAAAAAAA", nowUnixSecs: nowUnix)
    }
    #expect(throws: Error.self) {
      _ = try TendrilCrypto.verifyWakeTag(secret: secret, tagB64: "bad-tag", nowUnixSecs: nowUnix)
    }
    #expect(throws: Error.self) {
      _ = try TendrilCrypto.verifyWakeTag(secret: secret, tagB64: "AAAAAAAAAAAAAAAAAAAAAA\u{0}", nowUnixSecs: nowUnix)
    }

    // Bool, negative, fractional, and unaligned epoch_s values must be rejected cleanly.
    let validEpochS = (nowUnix / 3_600) * 3_600
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": true, "wake_tag": "tag", "epoch_s": validEpochS])
    }
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": 1, "wake_tag": "tag", "epoch_s": true])
    }
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": 2, "wake_tag": "tag", "epoch_s": validEpochS])
    }
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": 1, "wake_tag": "tag", "epoch_s": NSNumber(value: -1)])
    }
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": 1, "wake_tag": "tag", "epoch_s": NSNumber(value: Int64.min)])
    }
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": 1, "wake_tag": "tag", "epoch_s": NSNumber(value: 1.5)])
    }
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": 1, "wake_tag": "tag", "epoch_s": NSNumber(value: 1.0)])
    }
    #expect(throws: Error.self) {
      _ = try TendrilWakePayload(userInfo: ["v": 1, "wake_tag": "tag", "epoch_s": 120])
    }
    let validParsed = try TendrilWakePayload(userInfo: ["v": 1, "wake_tag": "tag", "epoch_s": validEpochS])
    #expect(validParsed.isWithinEpochWindow(nowUnixSecs: nowUnix))
    #expect(validParsed.isWithinEpochWindow(nowUnixSecs: nowUnix - 3_600))
    #expect(validParsed.isWithinEpochWindow(nowUnixSecs: nowUnix + 3_600))
    #expect(!validParsed.isWithinEpochWindow(nowUnixSecs: nowUnix + 7_200))
  }

  #if canImport(CryptoKit) && canImport(Security)
  @Test
  func tier1V2EciesEnvelopeRoundTripTamperMigrationAndAccessGroup() throws {
    let sePriv = P256.KeyAgreement.PrivateKey()
    let seAdapter = SoftwareKeyAgreementAdapter(sePriv)
    let legacyKey = SymmetricKey(size: .bits256)
    let cfg = TendrilKeychainConfiguration(
      service: "dev.tendril.state.test",
      account: "tier1-\(UUID().uuidString)",
      accessGroup: "TEAM123.dev.tendril.shared",
      custody: .secureEnclaveOrKeychain
    )
    let store = TendrilKeychainStore(
      configuration: cfg,
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { seAdapter }
    )

    let plaintext = Data("tier1-sep-ecies-secret-identity".utf8)
    let aad = Data("tendril.identity.v1".utf8)
    let sealedV2 = try store.sealState(plaintext, authenticating: aad)
    #expect(sealedV2.first == 0x02)
    // 1 (version) + 65 (x963 eph pub) + 12 (nonce) + plaintext.count + 16 (GCM tag)
    #expect(sealedV2.count == 1 + 65 + 12 + plaintext.count + 16)
    #expect(try store.openState(sealedV2, authenticating: aad) == plaintext)

    // Wrong AAD, tampered ephemeral key, tampered ciphertext/tag, truncated, and wrong SE key fail.
    #expect(throws: Error.self) {
      _ = try store.openState(sealedV2, authenticating: Data("wrong".utf8))
    }
    var badEph = sealedV2
    badEph[2] ^= 0x01
    #expect(throws: Error.self) {
      _ = try store.openState(badEph, authenticating: aad)
    }
    var badTag = sealedV2
    badTag[badTag.count - 1] ^= 0xFF
    #expect(throws: Error.self) {
      _ = try store.openState(badTag, authenticating: aad)
    }
    #expect(throws: Error.self) {
      _ = try store.openState(Data(sealedV2.prefix(66)), authenticating: aad)
    }
    let wrongSeStore = TendrilKeychainStore(
      configuration: cfg,
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter() }
    )
    #expect(throws: Error.self) {
      _ = try wrongSeStore.openState(sealedV2, authenticating: aad)
    }

    // Legacy 0x01 replay on a store that has already committed v2 custody must fail closed.
    let legacyStore = TendrilKeychainStore(
      service: cfg.service,
      account: cfg.account
    ) { legacyKey }
    let sealedV1 = try legacyStore.sealState(plaintext, authenticating: aad)
    #expect(sealedV1.first == 0x01)
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try store.openState(sealedV1, authenticating: aad)
    }

    // Explicit first-time migration succeeds once on a fresh v2 store and then locks out 0x01.
    let migrateStore = TendrilKeychainStore(
      configuration: cfg,
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { seAdapter }
    )
    let (upgraded, didUpgrade, migratedPlain) = try migrateStore.upgradeEnvelopeIfNeeded(
      sealedV1,
      authenticating: aad
    )
    #expect(didUpgrade)
    #expect(upgraded.first == 0x02)
    #expect(migratedPlain == plaintext)
    #expect(try migrateStore.openState(upgraded, authenticating: aad) == plaintext)
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try migrateStore.openState(sealedV1, authenticating: aad)
    }
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try migrateStore.upgradeEnvelopeIfNeeded(sealedV1, authenticating: aad)
    }

    // .secureEnclaveRequired rejects 0x01 downgrade in openState and refuses software fallback.
    let strictCfg = TendrilKeychainConfiguration(
      service: cfg.service,
      account: cfg.account,
      custody: .secureEnclaveRequired
    )
    let strictStore = TendrilKeychainStore(
      configuration: strictCfg,
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { seAdapter }
    )
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try strictStore.openState(sealedV1, authenticating: aad)
    }
    let strictSoftwareOnly = TendrilKeychainStore(
      configuration: strictCfg,
      customKeyProvider: { legacyKey }
    )
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try strictSoftwareOnly.sealState(plaintext, authenticating: aad)
    }

    // Once v2 custody is committed on a store, an injected provider failure must not silently
    // downgrade to 0x01.
    let shouldFail = AtomicBox(false)
    let noDowngradeStore = TendrilKeychainStore(
      configuration: cfg,
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: {
        if shouldFail.get() {
          throw TendrilKeychainError.secureEnclaveUnavailable
        }
        return seAdapter
      }
    )
    let initialV2 = try noDowngradeStore.sealState(plaintext, authenticating: aad)
    #expect(initialV2.first == 0x02)
    shouldFail.set(true)
    #expect(throws: TendrilKeychainError.secureEnclaveUnavailable) {
      _ = try noDowngradeStore.sealState(plaintext, authenticating: aad)
    }

    // Keychain access group & macOS Data Protection Keychain query assertions.
    let defaultStore = TendrilKeychainStore()
    let defaultSwQuery = defaultStore.keychainQueryBase(accountSuffix: "", isSepOrV2: false)
    #expect(defaultSwQuery[kSecAttrAccessGroup as String] == nil)
    #if os(macOS)
    #expect(defaultSwQuery[kSecUseDataProtectionKeychain as String] == nil)
    let defaultSepQuery = defaultStore.keychainQueryBase(accountSuffix: ".sep-p256", isSepOrV2: true)
    #expect(defaultSepQuery[kSecUseDataProtectionKeychain as String] as? Bool == true)
    #endif

    let sharedQuery = store.keychainQueryBase(accountSuffix: "", isSepOrV2: false)
    #expect(sharedQuery[kSecAttrAccessGroup as String] as? String == "TEAM123.dev.tendril.shared")
    #if os(macOS)
    #expect(sharedQuery[kSecUseDataProtectionKeychain as String] as? Bool == true)
    #endif
    #expect(defaultStore.configuration.accessControlFlags == [.privateKeyUsage])

    // Fallback policy allows entitlement/availability errors only and rejects CryptoKit or lock errors.
    #expect(TendrilKeychainStore.isFallbackEntitlementOrAvailabilityError(TendrilKeychainError.secureEnclaveUnavailable))
    #expect(TendrilKeychainStore.isFallbackEntitlementOrAvailabilityError(TendrilKeychainError.osStatus(-34018)))
    #expect(TendrilKeychainStore.isFallbackEntitlementOrAvailabilityError(TendrilMlDsa65Error.keychainStatus(errSecMissingEntitlement)))
    #expect(!TendrilKeychainStore.isFallbackEntitlementOrAvailabilityError(TendrilKeychainError.osStatus(errSecInteractionNotAllowed)))
    #expect(!TendrilKeychainStore.isFallbackEntitlementOrAvailabilityError(TendrilKeychainError.osStatus(errSecWrPerm)))
    #expect(!TendrilKeychainStore.isFallbackEntitlementOrAvailabilityError(CryptoKitError.authenticationFailure))
  }

  @Test
  func sealedSwiftStateStoreUpgradesV1IdentityAndAppliesClassC() throws {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent("tendril-mig-v2-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: dir) }
    try fm.createDirectory(at: dir, withIntermediateDirectories: true)

    let legacyKey = SymmetricKey(size: .bits256)
    let sePriv = P256.KeyAgreement.PrivateKey()
    let v1Store = TendrilKeychainStore(service: "dev.tendril.state.test", account: "mig-v2") { legacyKey }
    let v2Store = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(service: "dev.tendril.state.test", account: "mig-v2"),
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(sePriv) }
    )

    let legacyState = try SealedSwiftStateStore(dirPath: dir.path, keychain: v1Store)
    try legacyState.saveIdentityJson("{\"version\":1,\"dummy\":true}")
    let identityPath = dir.appendingPathComponent("identity.sealed").path
    let v1DiskBytes = try Data(contentsOf: URL(fileURLWithPath: identityPath))
    #expect(v1DiskBytes.first == 0x01)

    let upgradedState = try SealedSwiftStateStore(dirPath: dir.path, keychain: v2Store)
    let loaded = try upgradedState.loadIdentityJson()
    #expect(loaded == "{\"version\":1,\"dummy\":true}")
    #expect(try Data(contentsOf: URL(fileURLWithPath: identityPath)).first == 0x02)

    // Rollback to the captured 0x01 disk blob after upgrading must fail closed.
    try v1DiskBytes.write(to: URL(fileURLWithPath: identityPath))
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try upgradedState.loadIdentityJson()
    }

    #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
    let dirAttrs = try fm.attributesOfItem(atPath: dir.path)
    #expect(
      dirAttrs[.protectionKey] as? FileProtectionType == .completeUntilFirstUserAuthentication
    )
    let fileAttrs = try fm.attributesOfItem(atPath: identityPath)
    #expect(
      fileAttrs[.protectionKey] as? FileProtectionType == .completeUntilFirstUserAuthentication
    )
    #endif
  }

  @Test
  func tier2ExternalMlDsa65CustodyRoundTripAndWrongSignerRejected() throws {
    let fm = FileManager.default
    let base = fm.temporaryDirectory.appendingPathComponent("tendril-tier2-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: base) }

    let masterKey = SymmetricKey(size: .bits256)
    let seAdapter = SoftwareKeyAgreementAdapter()
    let kc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(service: "dev.tendril.state.test", account: "tier2"),
      customKeyProvider: { masterKey },
      customEnvelopeProvider: { seAdapter }
    )

    let signer1 = TestMlDsa65SoftwareKey(seed: Data(repeating: 0x51, count: 32))
    let wrongSigner = TestMlDsa65SoftwareKey(seed: Data(repeating: 0x77, count: 32))

    let hostDir = base.appendingPathComponent("host")
    let cliDir = base.appendingPathComponent("cli")
    let host1 = try TendrilEndpoint(
      stateDir: hostDir.path,
      hostId: "tier2-host",
      keychainStore: kc,
      options: TendrilEndpointOptions(mldsaSigner: signer1)
    )
    let info1 = try jsonObj(try host1.infoJson())
    let hostSigningPub = try #require(info1["signing_pub"] as? String)
    let listenEp = try host1.serveDirect(listenAddr: "127.0.0.1:0")
    let issued = try jsonObj(try host1.issuePairingUri())
    #expect((issued["uri"] as? String)?.contains("&rs=") == true)
    #expect(signer1.signCalls >= 1)

    // Verify identity.sealed was persisted with v2 external custody metadata.
    let sealedRaw = try Data(contentsOf: hostDir.appendingPathComponent("identity.sealed"))
    #expect(sealedRaw.first == 0x02)
    let savedId = try #require(try SealedSwiftStateStore(dirPath: hostDir.path, keychain: kc).loadIdentityJson())
    let savedObj = try jsonObj(savedId)
    #expect(savedObj["version"] as? Int == 2)
    #expect(savedObj["pq_signing_custody"] as? String == "external_mldsa65")
    #expect(savedObj["pq_signing_seed_b64"] == nil)

    // Pair and confirm a real client peer before minting a capability grant.
    let cliKey = SymmetricKey(size: .bits256)
    let cliSe = SoftwareKeyAgreementAdapter()
    let cliKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(service: "dev.tendril.state.test", account: "tier2-cli"),
      customKeyProvider: { cliKey },
      customEnvelopeProvider: { cliSe }
    )
    let cliEp = try TendrilEndpoint(stateDir: cliDir.path, hostId: "tier2-cli", keychainStore: cliKc)
    defer { cliEp.close() }
    let code = try host1.issueCode(kind: "lan")
    let pairSem = DispatchSemaphore(value: 0)
    let accBox = AtomicBox<String?>(nil)
    onDedicatedTestThread {
      accBox.set(try? host1.pairV2Accept(timeoutMs: 5_000))
      pairSem.signal()
    }
    let initRes = try jsonObj(try cliEp.pairV2Initiate(endpoint: listenEp, code: code, deviceName: "tier2-cli"))
    #expect(pairSem.wait(timeout: .now() + 5.0) == .success)
    let accObj = try jsonObj(try #require(accBox.get()))
    let sas = try #require(initRes["sas"] as? String)
    let cliDevId = try #require(accObj["device_id"] as? String)
    try host1.confirmPeer(peerId: cliDevId, sas: sas)
    try cliEp.confirmPeer(peerId: "tier2-host", sas: sas)

    let signCallsBeforeGrant = signer1.signCalls
    let grantJson = try host1.mintGrant(peerId: cliDevId, capsJson: "[\"fs.read\"]", ttlSecs: 300)
    #expect(signer1.signCalls > signCallsBeforeGrant)
    let keysJson = String(
      data: try JSONSerialization.data(withJSONObject: ["tier2-host": hostSigningPub]),
      encoding: .utf8
    )!
    #expect(
      try TendrilCrypto.verifyGrantJson(
        grantJson: grantJson,
        issuerKeysJson: keysJson,
        expectedSubject: cliDevId,
        expectedRootIssuer: "tier2-host",
        requestedCap: "fs.read",
        nowUnix: UInt64(Date().timeIntervalSince1970)
      )
    )
    host1.close()

    // Reopen without signer must fail closed (default options now opt out of fresh SEP creation).
    #expect(throws: Error.self) {
      _ = try TendrilEndpoint(
        stateDir: hostDir.path,
        hostId: "tier2-host",
        keychainStore: kc
      )
    }

    // Reopen with wrong signer must fail closed.
    #expect(throws: Error.self) {
      _ = try TendrilEndpoint(
        stateDir: hostDir.path,
        hostId: "tier2-host",
        keychainStore: kc,
        options: TendrilEndpointOptions(mldsaSigner: wrongSigner)
      )
    }

    // Reopen with matching signer succeeds, preserves identity, and signs new grants.
    let host2 = try TendrilEndpoint(
      stateDir: hostDir.path,
      hostId: "tier2-host",
      keychainStore: kc,
      options: TendrilEndpointOptions(mldsaSigner: signer1)
    )
    defer { host2.close() }
    let info2 = try jsonObj(try host2.infoJson())
    #expect(info2["device_id"] as? String == info1["device_id"] as? String)
    #expect(info2["signing_pub"] as? String == hostSigningPub)
    let callsBeforeReopenGrant = signer1.signCalls
    _ = try host2.mintGrant(peerId: cliDevId, capsJson: "[\"fs.read\"]", ttlSecs: 300)
    #expect(signer1.signCalls > callsBeforeReopenGrant)
  }

  @Test
  func wakeProcessorLoopbackEndToEndAndCancel() throws {
    let fm = FileManager.default
    let base = fm.temporaryDirectory.appendingPathComponent("tendril-wake-e2e-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: base) }

    let hostSe = SoftwareKeyAgreementAdapter()
    let cliSe = SoftwareKeyAgreementAdapter()
    let cliKey = SymmetricKey(size: .bits256)
    let hostKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(service: "dev.tendril.state.test", account: "wake-host"),
      customEnvelopeProvider: { hostSe }
    )
    let cliKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(service: "dev.tendril.state.test", account: "wake-cli"),
      customKeyProvider: { cliKey },
      customEnvelopeProvider: { cliSe }
    )

    let hostDir = base.appendingPathComponent("host")
    let cliDir = base.appendingPathComponent("cli")
    let host = try TendrilEndpoint(stateDir: hostDir.path, hostId: "wake-host", keychainStore: hostKc)
    defer { host.close() }

    _ = try host.serveDirect(listenAddr: "127.0.0.1:0")
    let uri = try jsonObj(try host.issuePairingUri())["uri"] as! String

    // Pair the extension client once so stored routes persist in rt-roster.sealed.
    let cliPair = try TendrilEndpoint(
      stateDir: cliDir.path,
      hostId: "wake-cli",
      keychainStore: cliKc,
      options: .extensionClientOnly
    )
    let pairSem = DispatchSemaphore(value: 0)
    let accBox = AtomicBox<String?>(nil)
    onDedicatedTestThread {
      accBox.set(try? host.pairV2Accept(timeoutMs: 5_000))
      pairSem.signal()
    }
    let pairRes = try jsonObj(try cliPair.pairV2Uri(uri, name: "ios-nse", deviceKind: "ios"))
    #expect(pairSem.wait(timeout: .now() + 5.0) == .success)
    let accObj = try jsonObj(try #require(accBox.get()))
    let sas = try #require(pairRes["sas"] as? String)
    let cliDevId = try #require(accObj["device_id"] as? String)
    try host.confirmPeer(peerId: cliDevId, sas: sas)
    cliPair.close()

    let grantJson = try host.mintGrant(peerId: cliDevId, capsJson: "[\"wake.notify\"]", ttlSecs: 300)

    // Compute valid wake_tag for current epoch.
    let wakeSecret = Data((0..<32).map { UInt8(0x44 + $0) })
    let nowUnix = UInt64(Date().timeIntervalSince1970)
    let epoch = nowUnix / 3600
    var salt = Data(count: 8)
    for i in 0..<8 {
      salt[i] = UInt8((epoch >> (56 - i * 8)) & 0xFF)
    }
    let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: wakeSecret), salt: salt)
    let tagKey = HKDF<SHA256>.expand(
      pseudoRandomKey: prk,
      info: Data("tendril/wake/epoch-tag/v1".utf8),
      outputByteCount: 16
    )
    let tagB64 = tagKey.withUnsafeBytes { Data($0) }.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")

    let userInfo: [AnyHashable: Any] = [
      "aps": ["mutable-content": 1, "alert": ["loc-key": "TENDRIL_WAKE_FALLBACK"]],
      "v": 1,
      "wake_tag": tagB64,
      "epoch_s": epoch * 3600,
    ]

    let processor = try TendrilWakeProcessor(
      stateDir: cliDir.path,
      hostId: "wake-cli",
      keychainStore: cliKc,
      peers: [
        TendrilWakePeer(peerId: "other-peer", wakeSecret: Data(repeating: 0x11, count: 32)),
        TendrilWakePeer(peerId: "wake-host", wakeSecret: wakeSecret, grantJson: grantJson),
      ],
      requiredCap: "wake.notify",
      wire: 2,
      budgetSecs: 5.0
    )

    // 1. Unmatched tag returns nil cleanly; out-of-window epoch_s fails closed.
    let unmatchedResult = try processor.process(
      userInfo: [
        "v": 1,
        "wake_tag": Data(repeating: 0x00, count: 16).base64EncodedString()
          .replacingOccurrences(of: "+", with: "-")
          .replacingOccurrences(of: "/", with: "_")
          .replacingOccurrences(of: "=", with: ""),
        "epoch_s": epoch * 3600,
      ],
      nowUnixSecs: nowUnix
    )
    #expect(unmatchedResult == nil)
    #expect(throws: Error.self) {
      _ = try processor.process(
        userInfo: [
          "v": 1,
          "wake_tag": tagB64,
          "epoch_s": (epoch + 2) * 3600,
        ],
        nowUnixSecs: nowUnix
      )
    }

    // 2. Host sends encrypted payload upon incoming v2 session; processor dials stored routes.
    let srvSem = DispatchSemaphore(value: 0)
    let clientDoneSem = DispatchSemaphore(value: 0)
    onDedicatedTestThread {
      if let srvSess = try? host.acceptV2(timeoutMs: 5_000) {
        try? srvSess.sendData(Data("wake-alert-payload".utf8))
        _ = clientDoneSem.wait(timeout: .now() + 5.0)
        srvSess.free()
      }
      srvSem.signal()
    }

    let delivered = AtomicBox<[Data]>([])
    let result = try processor.process(userInfo: userInfo, nowUnixSecs: nowUnix) { peerId, payload in
      #expect(peerId == "wake-host")
      delivered.modify { $0.append(payload) }
    }
    clientDoneSem.signal()
    #expect(srvSem.wait(timeout: .now() + 5.0) == .success)
    let unwrappedResult = try #require(result)
    #expect(unwrappedResult.peerId == "wake-host")
    #expect(unwrappedResult.messages == [Data("wake-alert-payload".utf8)])
    #expect(delivered.get() == [Data("wake-alert-payload".utf8)])

    // 3. Unauthorized capability fails before delivering any payload.
    let deniedDelivered = AtomicBox(false)
    let deniedProc = try TendrilWakeProcessor(
      stateDir: cliDir.path,
      hostId: "wake-cli",
      keychainStore: cliKc,
      peers: [TendrilWakePeer(peerId: "wake-host", wakeSecret: wakeSecret, grantJson: grantJson)],
      requiredCap: "shell.exec",
      wire: 2,
      budgetSecs: 5.0
    )
    let denySem = DispatchSemaphore(value: 0)
    let denyClientDoneSem = DispatchSemaphore(value: 0)
    onDedicatedTestThread {
      if let srvSess = try? host.acceptV2(timeoutMs: 5_000) {
        try? srvSess.sendData(Data("should-not-surface".utf8))
        _ = denyClientDoneSem.wait(timeout: .now() + 5.0)
        srvSess.free()
      }
      denySem.signal()
    }
    #expect(throws: Error.self) {
      _ = try deniedProc.process(userInfo: userInfo, nowUnixSecs: nowUnix) { _, _ in
        deniedDelivered.set(true)
      }
    }
    denyClientDoneSem.signal()
    #expect(denySem.wait(timeout: .now() + 5.0) == .success)
    #expect(!deniedDelivered.get())

    // 4. Cancellation (simulating serviceExtensionTimeWillExpire) aborts processing cleanly.
    let cancelProc = try TendrilWakeProcessor(
      stateDir: cliDir.path,
      hostId: "wake-cli",
      keychainStore: cliKc,
      peers: [TendrilWakePeer(peerId: "wake-host", wakeSecret: wakeSecret, grantJson: grantJson)],
      requiredCap: "wake.notify",
      wire: 2,
      budgetSecs: 10.0
    )
    let cancelSrvSem = DispatchSemaphore(value: 0)
    let procDoneForSrvSem = DispatchSemaphore(value: 0)
    let procDoneSem = DispatchSemaphore(value: 0)
    let gotFirstSem = DispatchSemaphore(value: 0)
    let cancelledSem = DispatchSemaphore(value: 0)
    let procErrorBox = AtomicBox<Error?>(nil)
    onDedicatedTestThread {
      let srv = try? host.acceptV2(timeoutMs: 5_000)
      if let srv {
        try? srv.sendData(Data("ready".utf8))
        _ = gotFirstSem.wait(timeout: .now() + 5.0)
        cancelProc.cancel()
        cancelledSem.signal()
        _ = procDoneForSrvSem.wait(timeout: .now() + 5.0)
        srv.free()
      }
      cancelSrvSem.signal()
    }
    onDedicatedTestThread {
      let cancelUserInfo: [AnyHashable: Any] = [
        "aps": ["mutable-content": 1, "alert": ["loc-key": "TENDRIL_WAKE_FALLBACK"]],
        "v": 1,
        "wake_tag": tagB64,
        "epoch_s": epoch * 3600,
      ]
      do {
        _ = try cancelProc.process(userInfo: cancelUserInfo, nowUnixSecs: nowUnix) { _, _ in
          gotFirstSem.signal()
          _ = cancelledSem.wait(timeout: .now() + 5.0)
        }
      } catch {
        procErrorBox.set(error)
      }
      procDoneForSrvSem.signal()
      procDoneSem.signal()
    }
    #expect(procDoneSem.wait(timeout: .now() + 5.0) == .success)
    #expect(cancelSrvSem.wait(timeout: .now() + 5.0) == .success)
    #expect(procErrorBox.get() as? TendrilError == TendrilError.closed)
  }

  private struct LegacyV1MigrationFixture {
    let root: TendrilEndpoint
    let legacyDir: URL
    let cliDevId: String
    let identityJson: String
    let rosterJson: String
    let v1IdentityBytes: Data
    let v1RosterBytes: Data
  }

  private func makeLegacyV1MigrationFixture(
    base: URL,
    account: String,
    legacyKey: SymmetricKey
  ) throws -> LegacyV1MigrationFixture {
    let fm = FileManager.default
    let rootDir = base.appendingPathComponent("root")
    let sourceDir = base.appendingPathComponent("source")
    let legacyDir = base.appendingPathComponent("legacy")
    try fm.createDirectory(at: base, withIntermediateDirectories: true)

    let rootKey = SymmetricKey(size: .bits256)
    let rootKc = TendrilKeychainStore(service: "dev.tendril.state.test", account: "\(account)-root") {
      rootKey
    }
    let v1Kc = TendrilKeychainStore(service: "dev.tendril.state.test", account: account) {
      legacyKey
    }

    let root = try TendrilEndpoint(stateDir: rootDir.path, hostId: "mig-root", keychainStore: rootKc)
    var success = false
    defer {
      if !success {
        root.close()
      }
    }
    _ = try root.serveDirect(listenAddr: "127.0.0.1:0")
    let uri = try jsonObj(try root.issuePairingUri())["uri"] as! String

    let sourceEp = try TendrilEndpoint(stateDir: sourceDir.path, hostId: "mig-cli", keychainStore: v1Kc)
    let pairSem = DispatchSemaphore(value: 0)
    let accBox = AtomicBox<String?>(nil)
    onDedicatedTestThread {
      accBox.set(try? root.pairV2Accept(timeoutMs: 5_000))
      pairSem.signal()
    }
    let pairRes = try jsonObj(try sourceEp.pairV2Uri(uri, name: "ios-mig", deviceKind: "ios"))
    #expect(pairSem.wait(timeout: .now() + 5.0) == .success)
    let accObj = try jsonObj(try #require(accBox.get()))
    let sas = try #require(pairRes["sas"] as? String)
    let cliDevId = try #require(accObj["device_id"] as? String)
    try root.confirmPeer(peerId: cliDevId, sas: sas)
    sourceEp.close()

    let identityJson = try #require(
      try SealedSwiftStateStore(dirPath: sourceDir.path, keychain: v1Kc).loadIdentityJson()
    )
    let rosterJson: String = try {
      let exportEp = sourceDir.path.withCString { cDir in
        identityJson.withCString { cId in tendril_endpoint_new_sealed(cDir, cId, nil, nil) }
      }
      let unwrappedExportEp = try #require(exportEp)
      defer { tendril_endpoint_free(unwrappedExportEp) }
      var rosterOut: UnsafeMutablePointer<CChar>?
      #expect(tendril_endpoint_export_roster_json(unwrappedExportEp, &rosterOut) == TENDRIL_OK.rawValue)
      let exported = String(cString: try #require(rosterOut))
      tendril_string_free(rosterOut)
      return exported
    }()

    try SealedSwiftStateStore(dirPath: legacyDir.path, keychain: v1Kc).saveIdentityJson(identityJson)
    let legacyIdentityPath = legacyDir.appendingPathComponent("identity.sealed")
    let v1IdentityBytes = try Data(contentsOf: legacyIdentityPath)
    #expect(v1IdentityBytes.first == 0x01)
    let legacyRosterPath = legacyDir.appendingPathComponent("roster.sealed")
    let v1RosterBytes = try v1Kc.sealState(
      Data(rosterJson.utf8),
      authenticating: Data("tendril.roster.v1".utf8)
    )
    #expect(v1RosterBytes.first == 0x01)
    try v1RosterBytes.write(to: legacyRosterPath)
    #expect(!fm.fileExists(atPath: legacyDir.appendingPathComponent("rt-roster.sealed").path))

    success = true
    return LegacyV1MigrationFixture(
      root: root,
      legacyDir: legacyDir,
      cliDevId: cliDevId,
      identityJson: identityJson,
      rosterJson: rosterJson,
      v1IdentityBytes: v1IdentityBytes,
      v1RosterBytes: v1RosterBytes
    )
  }

  private func verifyMigratedEndpointAndLockout(
    fixture: LegacyV1MigrationFixture,
    v2Store: TendrilKeychainStore
  ) throws {
    let fm = FileManager.default
    let migrated = try TendrilEndpoint(
      stateDir: fixture.legacyDir.path,
      hostId: "mig-cli",
      keychainStore: v2Store
    )
    defer { migrated.close() }

    #expect(fm.fileExists(atPath: fixture.legacyDir.appendingPathComponent("rt-roster.sealed").path))
    let routesObj = try jsonObj(try migrated.peerRoutes(peerId: "mig-root"))
    let routesList = try #require(routesObj["routes"] as? [[String: Any]])
    #expect(!routesList.isEmpty)

    let grant = try fixture.root.mintGrant(peerId: fixture.cliDevId, capsJson: "[\"fs.read\"]", ttlSecs: 300)
    let sessSem = DispatchSemaphore(value: 0)
    let srvSessBox = AtomicBox<TendrilSession?>(nil)
    onDedicatedTestThread {
      srvSessBox.set(try? fixture.root.acceptV2(timeoutMs: 5_000))
      sessSem.signal()
    }
    let cliSess = try migrated.connectV2(targetHostId: "mig-root", grantJson: grant)
    defer { cliSess.free() }
    #expect(sessSem.wait(timeout: .now() + 5.0) == .success)
    let srvSess = try #require(srvSessBox.get())
    defer { srvSess.free() }
    try cliSess.sendData(Data("migrated-v1-to-v2".utf8))
    let ev = try jsonObj(try srvSess.pollEvent(timeoutMs: 2_000))
    #expect(ev["event"] as? String == "data")

    #expect(!fm.fileExists(atPath: fixture.legacyDir.appendingPathComponent("roster.sealed").path))
    #expect((try Data(contentsOf: fixture.legacyDir.appendingPathComponent("identity.sealed"))).first == 0x02)

    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try v2Store.openState(fixture.v1RosterBytes, authenticating: Data("tendril.roster.v1".utf8))
    }
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try v2Store.openState(fixture.v1IdentityBytes, authenticating: Data("tendril.identity.v1".utf8))
    }
  }

  @Test
  func legacyV1IdentityAndRosterUpgradeToV2MigratesRosterAndRejectsReplay() throws {
    let fm = FileManager.default
    let base = fm.temporaryDirectory.appendingPathComponent("tendril-v1-v2-mig-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: base) }

    let legacyKey = SymmetricKey(size: .bits256)
    let sePriv = P256.KeyAgreement.PrivateKey()
    let account = "legacy-mig-\(UUID().uuidString)"
    let fixture = try makeLegacyV1MigrationFixture(base: base, account: account, legacyKey: legacyKey)
    defer { fixture.root.close() }

    let v2UpgradeKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: "dev.tendril.state.test",
        account: account,
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(sePriv) }
    )
    try verifyMigratedEndpointAndLockout(fixture: fixture, v2Store: v2UpgradeKc)
  }

  @Test
  func legacyV1MigrationSurvivesPreUpgradeIdentityLoadAndMidMigrationCrash() throws {
    let fm = FileManager.default
    let base = fm.temporaryDirectory.appendingPathComponent("tendril-v1-v2-crash-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: base) }

    // Case 1: standalone loadIdentityJson() upgrades identity.sealed to 0x02 while legacy
    // roster.sealed is still 0x01 and no rt-* files exist. V2 custody commit MUST stay deferred
    // so subsequent TendrilEndpoint open still upgrades roster.sealed, writes rt-roster.sealed,
    // deletes roster.sealed, and commits v2 custody.
    let key1 = SymmetricKey(size: .bits256)
    let se1 = P256.KeyAgreement.PrivateKey()
    let account1 = "legacy-case1-\(UUID().uuidString)"
    let fixture1 = try makeLegacyV1MigrationFixture(
      base: base.appendingPathComponent("case1"),
      account: account1,
      legacyKey: key1
    )
    defer { fixture1.root.close() }

    let v2Case1Kc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: "dev.tendril.state.test",
        account: account1,
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { key1 },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(se1) }
    )
    let preOpenStore = try SealedSwiftStateStore(dirPath: fixture1.legacyDir.path, keychain: v2Case1Kc)
    #expect(try preOpenStore.loadIdentityJson() == fixture1.identityJson)
    #expect((try Data(contentsOf: fixture1.legacyDir.appendingPathComponent("identity.sealed"))).first == 0x02)
    #expect((try Data(contentsOf: fixture1.legacyDir.appendingPathComponent("roster.sealed"))).first == 0x01)
    #expect(
      try v2Case1Kc.openState(fixture1.v1RosterBytes, authenticating: Data("tendril.roster.v1".utf8))
        == Data(fixture1.rosterJson.utf8)
    )
    try verifyMigratedEndpointAndLockout(fixture: fixture1, v2Store: v2Case1Kc)

    // Case 2: crash right after upgrading roster.sealed to 0x02 before identity.sealed upgrades.
    // A fresh store on restart opens 0x02 roster.sealed via openStateWithoutCommit, upgrades 0x01
    // identity.sealed to 0x02, writes rt-roster.sealed, deletes roster.sealed, and commits.
    let key2 = SymmetricKey(size: .bits256)
    let se2 = P256.KeyAgreement.PrivateKey()
    let account2 = "legacy-case2-\(UUID().uuidString)"
    let fixture2 = try makeLegacyV1MigrationFixture(
      base: base.appendingPathComponent("case2"),
      account: account2,
      legacyKey: key2
    )
    defer { fixture2.root.close() }

    let v2Case2PreCrashKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: "dev.tendril.state.test",
        account: account2,
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { key2 },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(se2) }
    )
    let crashStore = try SealedSwiftStateStore(
      dirPath: fixture2.legacyDir.path,
      keychain: v2Case2PreCrashKc,
      writeObserver: { fileName, _ in
        if fileName == "identity.sealed" {
          throw CocoaError(.fileWriteOutOfSpace)
        }
      }
    )
    #expect(try crashStore.loadRosterJson(upgradeIfNeeded: true, deferCommit: true) == fixture2.rosterJson)
    #expect((try Data(contentsOf: fixture2.legacyDir.appendingPathComponent("roster.sealed"))).first == 0x02)
    #expect(throws: CocoaError.self) {
      _ = try crashStore.loadIdentityJson(deferCommit: true)
    }
    #expect((try Data(contentsOf: fixture2.legacyDir.appendingPathComponent("identity.sealed"))).first == 0x01)
    #expect(!fm.fileExists(atPath: fixture2.legacyDir.appendingPathComponent("rt-roster.sealed").path))
    #expect(
      try v2Case2PreCrashKc.openState(
        fixture2.v1IdentityBytes,
        authenticating: Data("tendril.identity.v1".utf8)
      ) == Data(fixture2.identityJson.utf8)
    )

    let v2Case2RetryKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: "dev.tendril.state.test",
        account: account2,
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { key2 },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(se2) }
    )
    try verifyMigratedEndpointAndLockout(fixture: fixture2, v2Store: v2Case2RetryKc)

    // Case 3: TendrilEndpoint.openSealed upgrades both roster.sealed and identity.sealed to 0x02,
    // then newSealedWithOptions fails before rt-roster.sealed, deleteLegacyRoster, and commit;
    // a fresh TendrilEndpoint retry opens both 0x02 files, finishes migration, and commits.
    let key3 = SymmetricKey(size: .bits256)
    let se3 = P256.KeyAgreement.PrivateKey()
    let account3 = "legacy-case3-\(UUID().uuidString)"
    let fixture3 = try makeLegacyV1MigrationFixture(
      base: base.appendingPathComponent("case3"),
      account: account3,
      legacyKey: key3
    )
    defer { fixture3.root.close() }

    let v2Case3PrepKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: "dev.tendril.state.test",
        account: account3,
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { key3 },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(se3) }
    )
    #expect(throws: TendrilError.invalidArgument("hostId contains interior NUL byte")) {
      _ = try TendrilEndpoint(
        stateDir: fixture3.legacyDir.path,
        hostId: "bad\0host",
        keychainStore: v2Case3PrepKc
      )
    }
    #expect((try Data(contentsOf: fixture3.legacyDir.appendingPathComponent("roster.sealed"))).first == 0x02)
    #expect((try Data(contentsOf: fixture3.legacyDir.appendingPathComponent("identity.sealed"))).first == 0x02)
    #expect(!fm.fileExists(atPath: fixture3.legacyDir.appendingPathComponent("rt-roster.sealed").path))
    #expect(
      try v2Case3PrepKc.openState(fixture3.v1RosterBytes, authenticating: Data("tendril.roster.v1".utf8))
        == Data(fixture3.rosterJson.utf8)
    )

    let v2Case3RetryKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: "dev.tendril.state.test",
        account: account3,
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { key3 },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(se3) }
    )
    try verifyMigratedEndpointAndLockout(fixture: fixture3, v2Store: v2Case3RetryKc)
  }

  @Test
  func twoPhaseUpgradeSurvivesDiskFailureAndProbeErrorFailsClosed() throws {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent("tendril-two-phase-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: dir) }
    try fm.createDirectory(at: dir, withIntermediateDirectories: true)

    let legacyKey = SymmetricKey(size: .bits256)
    let sePriv = P256.KeyAgreement.PrivateKey()
    let cfg = TendrilKeychainConfiguration(
      service: "dev.tendril.state.test",
      account: "two-phase-\(UUID().uuidString)",
      custody: .secureEnclaveOrKeychain
    )
    let v1Kc = TendrilKeychainStore(service: cfg.service, account: cfg.account) { legacyKey }
    let aad = Data("tendril.two-phase.test".utf8)
    let plaintext = Data("two-phase-secret-payload".utf8)
    let v1Envelope = try v1Kc.sealState(plaintext, authenticating: aad)
    #expect(v1Envelope.first == 0x01)

    // (a1) Direct beginUpgradeV1ToV2 does not commit v2 until commitV2Custody() runs.
    let directStore = TendrilKeychainStore(
      configuration: cfg,
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(sePriv) }
    )
    let (upgraded, didUpgrade, upgradedPlain) = try directStore.beginUpgradeV1ToV2(
      v1Envelope,
      authenticating: aad
    )
    #expect(didUpgrade)
    #expect(upgraded.first == 0x02)
    #expect(upgradedPlain == plaintext)
    #expect(try directStore.openState(v1Envelope, authenticating: aad) == plaintext)

    try directStore.commitV2Custody()
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try directStore.openState(v1Envelope, authenticating: aad)
    }

    // (a2) Fault injection between beginUpgradeV1ToV2 and commitV2Custody leaves v1 readable
    // so retry finishes upgrading to 0x02, after which v1 replay fails closed.
    let v1State = try SealedSwiftStateStore(dirPath: dir.path, keychain: v1Kc)
    try v1State.saveIdentityJson("{\"version\":1,\"twoPhase\":true}")
    let idUrl = dir.appendingPathComponent("identity.sealed")
    let v1DiskBytes = try Data(contentsOf: idUrl)
    #expect(v1DiskBytes.first == 0x01)

    let injectFailure = AtomicBox(true)
    let twoPhaseKc = TendrilKeychainStore(
      configuration: cfg,
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(sePriv) }
    )
    let faultState = try SealedSwiftStateStore(
      dirPath: dir.path,
      keychain: twoPhaseKc,
      writeObserver: { fileName, _ in
        if fileName == "identity.sealed" && injectFailure.get() {
          throw CocoaError(.fileWriteOutOfSpace)
        }
      }
    )
    #expect(throws: CocoaError.self) {
      _ = try faultState.loadIdentityJson()
    }
    #expect((try Data(contentsOf: idUrl)).first == 0x01)

    injectFailure.set(false)
    #expect(try faultState.loadIdentityJson() == "{\"version\":1,\"twoPhase\":true}")
    #expect((try Data(contentsOf: idUrl)).first == 0x02)

    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try twoPhaseKc.openState(v1DiskBytes, authenticating: Data("tendril.identity.v1".utf8))
    }
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try twoPhaseKc.beginUpgradeV1ToV2(v1DiskBytes, authenticating: Data("tendril.identity.v1".utf8))
    }

    // (a3) Fault injection in syncDirectory() prevents v2 commit before the directory entry is durable;
    // retry completes directory sync and locks out subsequent v1 reads.
    let v1DirSyncStore = try SealedSwiftStateStore(dirPath: dir.path, keychain: v1Kc)
    try v1DirSyncStore.saveIdentityJson("{\"version\":1,\"dirSync\":true}")
    let v1DirSyncBytes = try Data(contentsOf: idUrl)
    #expect(v1DirSyncBytes.first == 0x01)

    let seSync = P256.KeyAgreement.PrivateKey()
    let syncKc = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: "dev.tendril.state.test",
        account: "\(cfg.account)-sync",
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { legacyKey },
      customEnvelopeProvider: { SoftwareKeyAgreementAdapter(seSync) }
    )
    let injectSyncFault = AtomicBox(true)
    let syncCalls = AtomicBox(0)
    let syncFaultState = try SealedSwiftStateStore(
      dirPath: dir.path,
      keychain: syncKc,
      syncDirObserver: {
        syncCalls.modify { $0 += 1 }
        if injectSyncFault.get() {
          throw CocoaError(.fileWriteUnknown)
        }
      }
    )
    #expect(throws: CocoaError.self) {
      _ = try syncFaultState.loadIdentityJson()
    }
    #expect(syncCalls.get() == 1)
    #expect(try syncKc.openState(v1DirSyncBytes, authenticating: Data("tendril.identity.v1".utf8)) == Data("{\"version\":1,\"dirSync\":true}".utf8))

    injectSyncFault.set(false)
    #expect(try syncFaultState.loadIdentityJson() == "{\"version\":1,\"dirSync\":true}")
    #expect(syncCalls.get() == 2)
    #expect((try Data(contentsOf: idUrl)).first == 0x02)
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try syncKc.openState(v1DirSyncBytes, authenticating: Data("tendril.identity.v1".utf8))
    }

    // (b) When v2CommitmentProbe throws an OSStatus read error, openState on v1 fails closed.
    let errProbeStore = TendrilKeychainStore(
      configuration: cfg,
      customKeyProvider: { legacyKey },
      v2CommitmentProbe: {
        throw TendrilKeychainError.osStatus(errSecInteractionNotAllowed)
      }
    )
    #expect(throws: TendrilKeychainError.osStatus(errSecInteractionNotAllowed)) {
      _ = try errProbeStore.openState(v1Envelope, authenticating: aad)
    }
    #expect(throws: TendrilKeychainError.osStatus(errSecInteractionNotAllowed)) {
      _ = try errProbeStore.beginUpgradeV1ToV2(v1Envelope, authenticating: aad)
    }

    let committedProbeStore = TendrilKeychainStore(
      configuration: cfg,
      customKeyProvider: { legacyKey },
      v2CommitmentProbe: { true }
    )
    #expect(throws: TendrilKeychainError.downgradeRejected) {
      _ = try committedProbeStore.openState(v1Envelope, authenticating: aad)
    }

    let missingEntDefault = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: cfg.service,
        account: cfg.account,
        accessGroup: nil,
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { legacyKey },
      v2CommitmentProbe: {
        throw TendrilKeychainError.osStatus(-34018)
      }
    )
    let missingEntGrouped = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: cfg.service,
        account: cfg.account,
        accessGroup: "TEAM123.dev.tendril.shared",
        custody: .secureEnclaveOrKeychain
      ),
      customKeyProvider: { legacyKey },
      v2CommitmentProbe: {
        throw TendrilKeychainError.osStatus(-34018)
      }
    )
    let missingEntSoftware = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: cfg.service,
        account: cfg.account,
        accessGroup: nil,
        custody: .keychainSoftware
      ),
      customKeyProvider: { legacyKey },
      v2CommitmentProbe: {
        throw TendrilKeychainError.osStatus(-34018)
      }
    )
    let missingEntSoftwareGrouped = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: cfg.service,
        account: cfg.account,
        accessGroup: "TEAM123.dev.tendril.shared",
        custody: .keychainSoftware
      ),
      customKeyProvider: { legacyKey },
      v2CommitmentProbe: {
        throw TendrilKeychainError.osStatus(-34018)
      }
    )
    let errProbeSoftware = TendrilKeychainStore(
      configuration: TendrilKeychainConfiguration(
        service: cfg.service,
        account: cfg.account,
        accessGroup: nil,
        custody: .keychainSoftware
      ),
      customKeyProvider: { legacyKey },
      v2CommitmentProbe: {
        throw TendrilKeychainError.osStatus(errSecInteractionNotAllowed)
      }
    )
    #if os(macOS)
    #expect(try missingEntDefault.openState(v1Envelope, authenticating: aad) == plaintext)
    #expect(try missingEntSoftware.openState(v1Envelope, authenticating: aad) == plaintext)
    #expect(try missingEntSoftware.sealState(plaintext, authenticating: aad).first == 0x01)
    #else
    #expect(throws: TendrilKeychainError.osStatus(-34018)) {
      _ = try missingEntDefault.openState(v1Envelope, authenticating: aad)
    }
    #expect(throws: TendrilKeychainError.osStatus(-34018)) {
      _ = try missingEntSoftware.openState(v1Envelope, authenticating: aad)
    }
    #endif
    #expect(throws: TendrilKeychainError.osStatus(-34018)) {
      _ = try missingEntGrouped.openState(v1Envelope, authenticating: aad)
    }
    #expect(throws: TendrilKeychainError.osStatus(-34018)) {
      _ = try missingEntSoftwareGrouped.openState(v1Envelope, authenticating: aad)
    }
    #expect(throws: TendrilKeychainError.osStatus(errSecInteractionNotAllowed)) {
      _ = try errProbeSoftware.openState(v1Envelope, authenticating: aad)
    }
    #expect(throws: TendrilKeychainError.osStatus(errSecInteractionNotAllowed)) {
      _ = try errProbeSoftware.sealState(plaintext, authenticating: aad)
    }
  }

  @Test
  func wakeProcessorRejectsEmptyRequiredCap() throws {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent("tendril-wake-cap-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: dir) }
    let key = SymmetricKey(size: .bits256)
    let kc = TendrilKeychainStore(
      service: "dev.tendril.state.test",
      account: "wake-cap-\(UUID().uuidString)"
    ) { key }
    for badCap in ["", "   ", "\n\t "] {
      #expect(throws: TendrilError.invalidArgument("requiredCap must not be empty")) {
        _ = try TendrilWakeProcessor(
          stateDir: dir.path,
          hostId: "wake-cap",
          keychainStore: kc,
          peers: [],
          requiredCap: badCap
        )
      }
      #if canImport(NetworkExtension) && (os(iOS) || os(visionOS))
      if #available(iOS 14.0, visionOS 1.0, *) {
        #expect(throws: TendrilError.invalidArgument("requiredCap must not be empty")) {
          _ = try TendrilLocalPushSession(
            stateDir: dir.path,
            hostId: "wake-cap",
            targetHostId: "peer-1",
            relayEndpoint: "wss://relay.example/v2/relay",
            requiredCap: badCap,
            onPayload: { _, _ in }
          )
        }
      }
      #endif
    }
  }
  #endif
}
