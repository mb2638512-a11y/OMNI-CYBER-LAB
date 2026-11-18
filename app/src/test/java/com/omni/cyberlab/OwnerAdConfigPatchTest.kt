package com.omni.cyberlab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OwnerAdConfigPatchTest {
    @Test
    fun patchesSupportedJsonXmlAndPropertiesFlags() {
        val source = """
            {
              "ads_enabled": true,
              "showAds": 1,
              "admob_app_id": "sample-id"
            }
            <bool name="enable_ads">true</bool>
            adsEnabled=true
        """.trimIndent()
        val (patched, count) = rewriteOwnerAdConfigText(source)
        assertEquals(4, count)
        assertTrue(patched.contains("\"ads_enabled\": false"))
        assertTrue(patched.contains("\"showAds\": 0"))
        assertTrue(patched.contains("<bool name=\"enable_ads\">false</bool>"))
        assertTrue(patched.contains("adsEnabled=false"))
        assertTrue(patched.contains("sample-id"))
    }

    @Test
    fun leavesDisabledAndUnrelatedSettingsUnchanged() {
        val source = """{"ads_enabled": false, "admob_app_id": "abc", "analytics_enabled": true}"""
        val (patched, count) = rewriteOwnerAdConfigText(source)
        assertEquals(0, count)
        assertEquals(source, patched)
    }
}