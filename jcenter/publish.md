
##Instructions for library publishing
Make sure that you have permissions to publish library:
 1) For AzureDevOps has unexpired access token with write permissions in AZURE_ARTIFACTS_ENV_ACCESS_TOKEN system environment variable
 2) For Bintray org account and access to Yubico org
 3) For Sonatype account should have access to com.yubico staging repos

Make sure that you put credentials into
> local.properties

Required properties:
 1) For AzureDevOps azureArtifactsGradleAccessToken
 2) For Bintray:  bintray.user and bintray.apikey, optional bintray.gpg.password
 3) For Sonatype sonatype.username, sonatype.password and signing.gnupg.keyName (name of your public key for release signature, this key should be uploaded to key server for validation)

Make sure that you have proper library version values in
> gradle.properties

example:
```
yubikitVersion=1.0.0-SNAPSHOT
```

Suffix -SNAPSHOT allows you to deploy different version on top of what was already deployed. 

Run this command in Terminal:
```
./gradlew  assembleRelease generatePomFileForAarPublication publish
```

To publish single module:
```
./gradlew  :yubikit:assembleRelease :yubikit:generatePomFileForAarPublication :yubikit:publish
```


Or publishing to bintray
```
./gradlew assembleRelease bintrayUpload
```
