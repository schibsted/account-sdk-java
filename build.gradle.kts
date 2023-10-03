import kotlin.io.encoding.Base64

plugins {
    `java-library`
    `maven-publish`
    signing
    alias(libs.plugins.nexus.publish)
}

version = "1.0.3"
group = "com.schibsted.account"

repositories {
    mavenCentral()
}

dependencies {
    api(libs.api.slf4j.api)

    implementation(libs.impl.konghq.unirest)
    implementation(libs.impl.nimbusds.oauth2.oidc.sdk)
    implementation(libs.impl.logback.classic)
    implementation(libs.impl.logback.core)

    implementation(libs.test.junit)
    implementation(libs.test.mockito)
}

java {
    withJavadocJar()
    withSourcesJar()

    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.test {
    addTestListener(
        object : TestListener {
            override fun beforeSuite(suite: TestDescriptor?) {}
            override fun afterSuite(suite: TestDescriptor?, result: TestResult?) {}

            override fun beforeTest(testDescriptor: TestDescriptor?) {
                logger.lifecycle("Running test: $testDescriptor")
            }

            override fun afterTest(testDescriptor: TestDescriptor?, result: TestResult?) {}

        }
    )
}


publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])

            pom {
                name.set("Schibsted account SDK Java")
                packaging = "jar"
                description.set("Schibsted account Java SDK ${project.version}")
                url.set("https://github.com/schibsted/account-sdk-java")

                scm {
                    connection.set("scm:git:https://github.com/schibsted/account-sdk-java.git")
                    url.set("https://github.com/schibsted/account-sdk-java")
                }

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                developers {
                    developer {
                        id.set("schibsted-account")
                        name.set("Schibsted account team")
                        email.set("schibstedaccount@schibsted.com")
                    }
                }
            }
        }
    }
}

nexusPublishing {
    this.repositories {
        sonatype()
    }
}

@OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)
signing {
    useInMemoryPgpKeys(
        System.getenv("SIGNING_KEY")
            ?.let(Base64::decode)
            ?.toString(Charsets.UTF_8),
        System.getenv("SIGNING_PASSWORD")
    )

    sign(publishing.publications["mavenJava"])
}
