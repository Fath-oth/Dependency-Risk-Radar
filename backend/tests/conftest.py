# backend/tests/conftest.py
import sys
import os
import pytest

# Add backend root to path so `app` is importable without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def sample_gradle_content():
    return """
plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
}

android {
    compileSdk 34
    defaultConfig {
        applicationId "com.example.myapp"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0.0"
    }
}

def retrofitVersion = "2.9.0"

dependencies {
    implementation "com.squareup.retrofit2:retrofit:$retrofitVersion"
    implementation "com.squareup.retrofit2:converter-gson:$retrofitVersion"
    implementation 'com.google.code.gson:gson:2.10.1'
    implementation 'com.squareup.okhttp3:okhttp:4.11.0'
    implementation 'com.squareup.okhttp3:logging-interceptor:4.11.0'
    implementation 'io.reactivex.rxjava3:rxjava:3.1.6'
    implementation 'io.reactivex.rxjava3:rxandroid:3.0.2'
    implementation 'com.google.dagger:dagger:2.48'
    kapt 'com.google.dagger:dagger-compiler:2.48'
    implementation 'org.jetbrains.kotlin:kotlin-stdlib:1.9.0'
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
    testImplementation 'junit:junit:4.13.2'
    androidTestImplementation 'androidx.test.ext:junit:1.1.5'
}
"""


@pytest.fixture
def sample_gradle_tree():
    return """
> Task :app:dependencies

------------------------------------------------------------
Project ':app'
------------------------------------------------------------

releaseRuntimeClasspath - Resolved configuration for runtime for variant: release
+--- com.squareup.retrofit2:retrofit:2.9.0
|    +--- com.squareup.okhttp3:okhttp:4.11.0
|    |    +--- com.squareup.okio:okio:3.6.0
|    |    |    \\--- org.jetbrains.kotlin:kotlin-stdlib:1.9.21
|    |    \\--- com.squareup.okio:okio-jvm:3.6.0
|    \\--- com.squareup.okhttp3:okhttp-bom:4.11.0
+--- com.google.code.gson:gson:2.10.1
+--- io.reactivex.rxjava3:rxjava:3.1.6
|    \\--- org.reactivestreams:reactive-streams:1.0.4
\\--- org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3
     \\--- org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3
          \\--- org.jetbrains.kotlin:kotlin-stdlib:1.9.21

BUILD SUCCESSFUL in 3s
"""
