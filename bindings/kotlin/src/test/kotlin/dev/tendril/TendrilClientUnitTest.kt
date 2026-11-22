package dev.tendril

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TendrilClientUnitTest {
  @Test
  fun keystoreCipherRejectsShortPayload() {
    val cipher = KeystoreStateCipher("tendril.unit.test.v1")
    val err =
      runCatching { cipher.decrypt(byteArrayOf(1, 2, 3)) }
        .exceptionOrNull()
    assertTrue(err is IllegalArgumentException)
    assertEquals("sealed payload too short", err?.message)
  }

  @Test
  fun keystoreCipherRejectsUnsupportedVersion() {
    val cipher = KeystoreStateCipher("tendril.unit.test.v1")
    val bad = ByteArray(32) { 99 }
    val err =
      runCatching { cipher.decrypt(bad) }
        .exceptionOrNull()
    assertTrue(err is IllegalArgumentException)
    assertEquals("unsupported sealed version: 99", err?.message)
  }

  @Test
  fun sealedStateStoreRejectsNonDirectoryAndMissingFilesReturnNull() {
    val tmpDir = Files.createTempDirectory("tendril-unit-state-")
    try {
      val store = SealedStateStore(tmpDir.toString(), KeystoreStateCipher("tendril.unit.test.v1"))
      assertNull(store.loadIdentityJson())
      assertNull(store.loadRosterJson())

      val regularFile = Files.createTempFile(tmpDir, "not-a-dir-", ".txt")
      val dirErr =
        runCatching { SealedStateStore(regularFile.toString(), KeystoreStateCipher("tendril.unit.test.v1")) }
          .exceptionOrNull()
      assertTrue(dirErr is IllegalArgumentException)
      assertEquals("stateDir must be a private directory", dirErr?.message)

      val fakeSealedDir = tmpDir.resolve("identity.sealed")
      Files.createDirectory(fakeSealedDir)
      val fileErr =
        runCatching { store.loadIdentityJson() }
          .exceptionOrNull()
      assertTrue(fileErr is IllegalArgumentException)
      assertEquals("sealed state file 'identity.sealed' must be a regular file", fileErr?.message)
    } finally {
      tmpDir.toFile().deleteRecursively()
    }
  }

  @Test
  fun tendrilEndpointAndNativeExposeWaveDV2Methods() {
    val epMethods = TendrilEndpoint::class.java.declaredMethods.map { it.name }.toSet()
    val expectedEp =
      listOf(
        "configureTransportsJson",
        "mintRelayTicket",
        "serveRelayV2",
        "pairV2Initiate",
        "pairV2Accept",
        "connectV2",
        "acceptV2",
      )
    for (name in expectedEp) {
      assertTrue("missing TendrilEndpoint.$name", epMethods.contains(name))
    }

    val nativeMethods = TendrilNative::class.java.declaredMethods.map { it.name }.toSet()
    val expectedNative =
      listOf(
        "endpointConfigureTransportsJson",
        "endpointMintRelayTicket",
        "endpointServeRelayV2",
        "endpointPairV2Initiate",
        "endpointPairV2Accept",
        "sessionConnectV2",
        "sessionAcceptV2",
      )
    for (name in expectedNative) {
      assertTrue("missing TendrilNative.$name", nativeMethods.contains(name))
    }
  }

  @Test
  fun tendrilEndpointGroupAndNativeExposeGroupMethods() {
    val epMethods = TendrilEndpoint::class.java.declaredMethods.map { it.name }.toSet()
    for (name in
      listOf(
        "groupCreate",
        "groupAddMember",
        "groupRemoveMember",
        "groupIngestManifest",
        "openGroup",
      )) {
      assertTrue("missing TendrilEndpoint.$name", epMethods.contains(name))
    }

    val groupMethods = TendrilGroup::class.java.declaredMethods.map { it.name }.toSet()
    for (name in listOf("broadcast", "sync", "localEndpoint", "pollEvent", "authorizePeer", "close")) {
      assertTrue("missing TendrilGroup.$name", groupMethods.contains(name))
    }

    val nativeMethods = TendrilNative::class.java.declaredMethods.map { it.name }.toSet()
    for (name in
      listOf(
        "groupCreate",
        "groupAddMember",
        "groupRemoveMember",
        "groupIngestManifest",
        "groupOpen",
        "groupLocalEndpoint",
        "groupSync",
        "groupBroadcast",
        "groupPollEvent",
        "groupAuthorizePeer",
        "groupClose",
        "groupFree",
      )) {
      assertTrue("missing TendrilNative.$name", nativeMethods.contains(name))
    }
  }
}
