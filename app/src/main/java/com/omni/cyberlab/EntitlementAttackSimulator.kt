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
            val p=Purchase("replay-token","com.omni.demo","coins_100","alice","PURCHASED",true);val strong=DemoBackend(true)
            strong.grant(p,"alice");val second=strong.grant(p,"alice")
            add("replay","Purchase-token replay","Submit the same purchase token twice.","ALLOW • vulnerable implementation can double-credit",second,true,"Hardened wallet balance=${strong.coins("alice")} coins; one 100-coin credit expected.")
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
        return out
    }
}
