package com.omni.cyberlab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EntitlementAttackSimulatorTest {
    @Test
    fun suiteContainsAllExpectedAttackScenarios() {
        val results = EntitlementAttackSimulator.runSuite()
        assertEquals(12, results.size)
        assertEquals(
            setOf("fake_receipt", "pending", "replay", "account_swap", "wrong_sku", "local_flag", "negative_spend", "client_amount", "expired_vip", "refunded", "token_product_swap", "zero_spend"),
            results.map { it.id }.toSet()
        )
    }

    @Test
    fun everyScenarioHasEvidenceAndBothOutcomes() {
        EntitlementAttackSimulator.runSuite().forEach { result ->
            assertTrue("Missing title for ${result.id}", result.title.isNotBlank())
            assertTrue("Missing attack description for ${result.id}", result.attackerTechnique.isNotBlank())
            assertTrue("Missing vulnerable outcome for ${result.id}", result.vulnerableOutcome.isNotBlank())
            assertTrue("Missing hardened outcome for ${result.id}", result.hardenedOutcome.isNotBlank())
            assertTrue("Missing evidence for ${result.id}", result.evidence.isNotBlank())
        }
    }

    @Test
    fun knownWeakControlsAreDetected() {
        val results = EntitlementAttackSimulator.runSuite().associateBy { it.id }
        listOf("fake_receipt", "pending", "replay", "account_swap", "wrong_sku", "local_flag", "negative_spend", "client_amount", "expired_vip", "refunded", "token_product_swap", "zero_spend")
            .forEach { id -> assertTrue("Expected vulnerable demo: $id", results[id]?.vulnerable == true) }
    }

    @Test
    fun hardenedControlsRejectForgedAndPendingPurchases() {
        val results = EntitlementAttackSimulator.runSuite().associateBy { it.id }
        assertTrue(results.getValue("fake_receipt").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("pending").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("account_swap").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("wrong_sku").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("negative_spend").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("client_amount").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("expired_vip").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("refunded").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("token_product_swap").hardenedOutcome.startsWith("DENY"))
        assertTrue(results.getValue("zero_spend").hardenedOutcome.startsWith("DENY"))
    }

    @Test
    fun replayOnlyCreditsOneHundredCoinsInHardenedDemo() {
        val replay = EntitlementAttackSimulator.runSuite().first { it.id == "replay" }
        assertTrue(replay.hardenedOutcome.startsWith("DENY"))
        assertTrue(replay.evidence.contains("100 coins"))
    }

    @Test
    fun localFlagTamperingDoesNotGrantHardenedVip() {
        val result = EntitlementAttackSimulator.runSuite().first { it.id == "local_flag" }
        assertTrue(result.vulnerableOutcome.contains("UNLOCKED"))
        assertTrue(result.hardenedOutcome.contains("DENIED"))
    }
}
