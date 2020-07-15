
##Instructions for library publishing
Make sure that you have permissions to publish in Yubico's Sonatype group.

Make sure that you put your credentials into:
> ~/.gradle/gradle.properties

Example gradle.properties:
```
signing.gnupg.executable=gpg
signing.gnupg.keyName=<your_gpg_key_id>

sonatype.username=<your_username>
sonatype.password=<your_password>
```

Make sure that you have the desired library version values in the top level
> build.gradle

example:
```
subprojects {
    version = '1.0.0-SNAPSHOT'
}
```

Suffix -SNAPSHOT allows you to deploy different version on top of what was already deployed.


As a dry run, publish to your local Maven repository (~/.m2/):
```
./gradlew publishToMavenLocal
```


Run this command in Terminal:
```
./gradlew  assembleRelease generatePomFileForAarPublication publish
```

To publish single module:
```
./gradlew  :yubikit:assembleRelease :yubikit:generatePomFileForAarPublication :yubikit:publish
```
