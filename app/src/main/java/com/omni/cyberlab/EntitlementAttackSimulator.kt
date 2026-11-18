package com.omni.cyberlab

data class EntitlementSimulationResult(
    val id: String, val title: String, val attackerTechnique: String,
    val vulnerableOutcome: String, val hardenedOutcome: String,
    val vulnerable: Boolean, val evidence: String
)

/** Local-only toy backend. Never reads, patches, launches or contacts another app. */
object EntitlementAttackSimulator {
    private data class Purchase(val token:String,val packageName:String,val productId:String,val accountId:String,val state:String,val verified:Boolean)
    private class DemoBackend(private val hardened:Boolean) {
        private val consumed=mutableSetOf<String>()
        private val entitlements=mutableSetOf<String>()
        private val wallet=mutableMapOf<String,Long>()
        fun grant(p:Purchase,account:String,requestedCoins:Long=0):String {
            if(hardened) {
                if(!p.verified)return "DENY • token not verified"
                if(p.state!="PURCHASED")return "DENY • state is ${p.state}"
                if(p.packageName!="com.omni.demo"||p.productId !in setOf("vip_monthly","coins_100"))return "DENY • package/product mismatch"
                if(p.accountId!=account)return "DENY • account binding mismatch"
                if(!consumed.add(p.token))return "DENY • duplicate token"
                if(p.productId=="vip_monthly")entitlements.add(account)
                if(p.productId=="coins_100")wallet[account]=(wallet[account]?:0L)+100L
                return "ALLOW • verified and fulfilled once"
            }
            if(p.productId=="vip_monthly")entitlements.add(account)
            if(p.productId=="coins_100")wallet[account]=(wallet[account]?:0L)+requestedCoins
            return "ALLOW • vulnerable client-trusted grant"
        }
        fun hasVip(account:String,clientFlag:Boolean)=if(hardened)account in entitlements else clientFlag||account in entitlements
        fun coins(account:String)=wallet[account]?:0L
        fun spend(account:String,amount:Long):String {
            val balance=wallet[account]?:0L
            if(hardened&&(amount<=0L||amount>balance))return "DENY • invalid amount / insufficient balance"
            wallet[account]=balance-amount
            return "ALLOW • demo balance ${wallet[account]}"
        }
    }
    fun runSuite():List<EntitlementSimulationResult> {
        val out=mutableListOf<EntitlementSimulationResult>()
        fun add(id:String,title:String,tech:String,weak:String,strong:String,vuln:Boolean,evidence:String){
            out+=EntitlementSimulationResult(id,title,tech,weak,strong,vuln,evidence)
        }
        run {
            val p=Purchase("fake-token","com.omni.demo","vip_monthly","alice","PURCHASED",false)
            val a=DemoBackend(false).grant(p,"alice");val b=DemoBackend(true).grant(p,"alice")
            add("fake_receipt","Forged purchase token","Submit fabricated token with client-claimed PURCHASED state.",a,b,a.startsWith("ALLOW"),"Token verified=false.")
        }
        run {
            val p=Purchase("pending-token","com.omni.demo","vip_monthly","alice","PENDING",true)
            val a=DemoBackend(false).grant(p,"alice");val b=DemoBackend(true).grant(p,"alice")
            add("pending","Pending purchase unlock","Attempt to fulfill a PENDING transaction.",a,b,a.startsWith("ALLOW"),"Provider state=PENDING.")
        }
        run {
            val p=Purchase("replay-token","com.omni.demo","coins_100","alice","PURCHASED",true)
            val weak=DemoBackend(false);val strong=DemoBackend(true)
            weak.grant(p,"alice",100);val weakSecond=weak.grant(p,"alice",100)
            strong.grant(p,"alice");val strongSecond=strong.grant(p,"alice")
            add("replay","Purchase-token replay","Submit the same purchase token twice.","${weakSecond} • vulnerable balance=${weak.coins("alice")} coins",strongSecond,weak.coins("alice")>100,"Vulnerable demo credits twice (${weak.coins("alice")}); hardened demo balance=${strong.coins("alice")} coins.")
        }
        run {
            val p=Purchase("bound-token","com.omni.demo","vip_monthly","alice","PURCHASED",true)
            val a=DemoBackend(false).grant(p,"bob");val b=DemoBackend(true).grant(p,"bob")
            add("account_swap","Cross-account entitlement transfer","Redeem Alice's purchase as Bob.",a,b,a.startsWith("ALLOW"),"Purchase owner=alice; requested account=bob.")
        }
        run {
            val p=Purchase("wrong-sku","com.other.app","vip_yearly","alice","PURCHASED",true)
            val a=DemoBackend(false).grant(p,"alice");val b=DemoBackend(true).grant(p,"alice")
            add("wrong_sku","Wrong package / SKU","Present token from a different app and product.",a,b,a.startsWith("ALLOW"),"Expected com.omni.demo / vip_monthly.")
        }
        run {
            val a=DemoBackend(false).hasVip("alice",true);val b=DemoBackend(true).hasVip("alice",true)
            add("local_flag","Local VIP boolean tampering","Flip a local isPremium flag without a verified entitlement.","VIP check=${if(a)"UNLOCKED" else "LOCKED"}","Protected entitlement=${if(b)"GRANTED" else "DENIED"}",a&&!b,"Client-controlled boolean must not authorize protected server actions.")
        }
        run {
            val a=DemoBackend(false).spend("alice",-500);val b=DemoBackend(true).spend("alice",-500)
            add("negative_spend","Negative amount / balance inflation","Submit a negative spend amount.",a,b,a.startsWith("ALLOW"),"Negative values must be rejected before ledger mutation.")
        }
        run {
            val weak=DemoBackend(false);val strong=DemoBackend(true)
            val a=weak.grant(Purchase("client-price","com.omni.demo","coins_100","alice","PURCHASED",false),"alice",999999)
            val b=strong.grant(Purchase("client-price","com.omni.demo","coins_100","alice","PURCHASED",false),"alice",999999)
            add("client_amount","Client-edited currency quantity","Request arbitrary coins from an untrusted client.","$a • balance=${weak.coins("alice")}","$b • balance=${strong.coins("alice")}",weak.coins("alice")>100,"Trusted product catalog must determine grants.")
        }

        run {
            val p=Purchase("expired-token","com.omni.demo","vip_monthly","alice","EXPIRED",true)
            val a=DemoBackend(false).grant(p,"alice");val b=DemoBackend(true).grant(p,"alice")
            add("expired_vip","Expired VIP renewal","Replay a previously valid but expired subscription state.",a,b,a.startsWith("ALLOW"),"Provider state=EXPIRED; protected access must stop at expiry.")
        }
        run {
            val p=Purchase("refunded-token","com.omni.demo","vip_monthly","alice","REFUNDED",true)
            val a=DemoBackend(false).grant(p,"alice");val b=DemoBackend(true).grant(p,"alice")
            add("refunded","Refunded purchase replay","Attempt to restore VIP from a refunded purchase.",a,b,a.startsWith("ALLOW"),"Provider state=REFUNDED; entitlement must be revoked.")
        }
        run {
            val weak=DemoBackend(false);val strong=DemoBackend(true)
            val first=Purchase("swapped-token","com.omni.demo","vip_monthly","alice","PURCHASED",true)
            val second=Purchase("swapped-token","com.omni.demo","coins_100","alice","PURCHASED",true)
            weak.grant(first,"alice");val a=weak.grant(second,"alice",999)
            strong.grant(first,"alice");val b=strong.grant(second,"alice",999)
            add("token_product_swap","Token reused for another product","Reuse a verified purchase token against a different SKU.",a,b,a.startsWith("ALLOW"),"One purchase token must bind to one product identity.")
        }
        run {
            val a=DemoBackend(false).spend("alice",0);val b=DemoBackend(true).spend("alice",0)
            add("zero_spend","Zero-value wallet spend","Submit a zero-value transaction to pollute the wallet ledger.",a,b,a.startsWith("ALLOW"),"Zero and negative amounts must be rejected.")
        }
        return out
    }
}


/** Owner-side QA checks for ad configuration and license enforcement. No APK patch is applied. */
object OwnerPatchQaSimulator {
    fun runSuite(): List<EntitlementSimulationResult> = listOf(
        EntitlementSimulationResult(
            "owner_ad_config", "Owner ad-disable configuration test",
            "Exercise an owner-controlled staging flag that disables ad requests for a test build.",
            "Unscoped patching can remove ad calls while leaving consent, reward callbacks or app startup in an inconsistent state.",
            "PASS only when the owner's explicit staging flag disables ad loading, consent remains respected, and rewarded inventory is not granted without verified completion.",
            true, "Local policy fixture only; no ad SDK call, APK mutation or third-party app modification."
        ),
        EntitlementSimulationResult(
            "ad_reward_spoof", "Rewarded-ad callback spoof resistance",
            "Invoke a local mock completion callback without a verified reward event.",
            "Client-trusted callback grants the configured reward.",
            "Reject the callback unless the owner test adapter supplies a verified reward event and unique event ID.",
            true, "Local callback model; no real ad network contacted and no reward credited."
        ),
        EntitlementSimulationResult(
            "license_client_flag", "Client-side license flag tampering",
            "Flip an owner test build's local license-valid flag while offline.",
            "A client-only license flag may show protected UI as licensed.",
            "Protected server operations remain denied until the owner backend validates the license and account binding.",
            true, "Local license-state fixture; no license key generated, altered or applied to another app."
        ),
        EntitlementSimulationResult(
            "license_expiry", "License expiry / clock rollback resistance",
            "Simulate an expired license and a device-clock rollback in the owner test harness.",
            "A client-only expiry check may accept stale local state.",
            "Backend expiry and revocation state remain authoritative; client clock is advisory only.",
            true, "Deterministic local state model; no external license server contacted."
        )
    )
}
