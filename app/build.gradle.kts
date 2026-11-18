plugins {
 id("com.android.application")
 id("org.jetbrains.kotlin.android")
 id("org.jetbrains.kotlin.plugin.compose")
}
android {
 namespace = "com.omni.cyberlab"
 compileSdk = 35
 defaultConfig {
  applicationId = "com.omni.cyberlab"
  minSdk = 26
  targetSdk = 35
  versionCode = 11
  versionName = "0.11.0"
 }
 compileOptions {
  sourceCompatibility = JavaVersion.VERSION_17
  targetCompatibility = JavaVersion.VERSION_17
 }
 kotlinOptions {
  jvmTarget = "17"
 }
 buildFeatures { compose = true }
}
dependencies {
 implementation(platform("androidx.compose:compose-bom:2024.12.01"))
 implementation("androidx.activity:activity-compose:1.10.0")
 implementation("androidx.core:core-ktx:1.15.0")
 implementation("androidx.compose.ui:ui")
 implementation("androidx.compose.ui:ui-tooling-preview")
 implementation("androidx.compose.material3:material3")
 implementation("androidx.compose.material:material-icons-extended")
 implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
 implementation("dev.rikka.shizuku:api:13.1.5")
 implementation("dev.rikka.shizuku:provider:13.1.5")
 implementation("com.android.tools.build:apksig:8.7.3")
 implementation("org.smali:baksmali:2.5.2")
 implementation("org.smali:dexlib2:2.5.2")
 implementation("org.smali:smali:2.5.2")
 implementation("net.dongliu:apk-parser:2.6.10")
 testImplementation("junit:junit:4.13.2")
 debugImplementation("androidx.compose.ui:ui-tooling")
}
