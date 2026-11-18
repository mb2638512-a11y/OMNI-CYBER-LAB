package com.omni.cyberlab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class TamperProbeTest {
    @Test
    fun addsOnlyInertMarkerAndDropsStaleSignatureMetadata() {
        val dir = createTempDir(prefix = "lucky-tamper-test")
        try {
            val source = File(dir, "source.apk")
            ZipOutputStream(source.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml")); zip.write(byteArrayOf(1, 2, 3)); zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex")); zip.write(byteArrayOf(4, 5, 6)); zip.closeEntry()
                zip.putNextEntry(ZipEntry("META-INF/CERT.RSA")); zip.write(byteArrayOf(7)); zip.closeEntry()
                zip.putNextEntry(ZipEntry("META-INF/MANIFEST.MF")); zip.write("Manifest".toByteArray()); zip.closeEntry()
            }
            val output = File(dir, "probe.apk")
            buildTamperProbeApk(source, output)
            ZipFile(output).use { zip ->
                assertNotNull(zip.getEntry("AndroidManifest.xml"))
                assertNotNull(zip.getEntry("classes.dex"))
                assertNull(zip.getEntry("META-INF/CERT.RSA"))
                assertNull(zip.getEntry("META-INF/MANIFEST.MF"))
                val marker = zip.getInputStream(zip.getEntry("assets/lucky_patches_tamper_probe.txt")).bufferedReader().use { it.readText() }
                assertTrue(marker.contains("inert asset insertion only"))
                assertEquals(3, zip.size())
            }
            ZipFile(source).use { zip ->
                assertNotNull(zip.getEntry("META-INF/CERT.RSA"))
                assertEquals(4, zip.size())
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun refusesDuplicateProbeMarker() {
        val dir = createTempDir(prefix = "lucky-tamper-duplicate")
        try {
            val source = File(dir, "source.apk")
            ZipOutputStream(source.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("assets/lucky_patches_tamper_probe.txt"))
                zip.write("already present".toByteArray())
                zip.closeEntry()
            }
            val output = File(dir, "probe.apk")
            var failed = false
            try { buildTamperProbeApk(source, output) } catch (_: IllegalArgumentException) { failed = true }
            assertTrue(failed)
            assertFalse(output.length() > 0L)
        } finally {
            dir.deleteRecursively()
        }
    }
}
