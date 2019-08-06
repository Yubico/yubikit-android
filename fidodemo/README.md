# Introduction 
FIDO 2 demo shows a complete example on how to use Yubikit library for FIDO2 including requests from server and validation.

# Integration
Include this submodule in your gradle file
```
    implementation project(":fidodemo")
```
and in settings.gradle
```
, ':fidodemo'
```
Take advantage of this library you need 
1. To implement Activity and derive it from `FidoActivity`
2. To create a navigation graph with fragment navigation and have 3 main components:
 - @+id/suggested_accounts_fragment (use default implementation `com.yubico.yubikit.demo.fido.SuggestedAccountsFragment` and `@layout/fragment_suggested_accounts`)
 - @+id/login_fragment (use default implementation `com.yubico.yubikit.demo.fido.LoginFragment` and `@layout/fragment_login`)
 - @+id/main_fragment (may be your screen after log in operation)
 
 `com.yubico.yubikit.demo.fido.AuthenticatorListFragment` is available for showing list of authenticators for user (optional)
 
 Sample:
```xml
<navigation xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:id="@+id/mobile_navigation"
    app:startDestination="@id/splash_fragment">

    <fragment
        android:id="@+id/splash_fragment"
        android:name="com.yubico.yubikit.demo.SplashFragment"
        android:label="SplashFragment"
        tools:layout="@layout/fragment_layout_splash">
    </fragment>
    <fragment
        android:id="@+id/suggested_accounts_fragment"
        android:name="com.yubico.yubikit.demo.fido.signin.SuggestedAccountsFragment"
        android:label="@string/sign_in_as"
        tools:layout="@layout/fragment_suggested_accounts">
    </fragment>
    <fragment
        android:id="@+id/login_fragment"
        android:name="com.yubico.yubikit.demo.fido.signin.LoginFragment"
        android:label="@string/action_sign_in"
        tools:layout="@layout/fragment_login" >
    </fragment>
    <fragment
        android:id="@+id/main_fragment"
        android:name="com.yubico.yubikit.demo.fido.listview.AuthenticatorListFragment"
        android:label="@string/title_activity_main"
        tools:layout="@layout/fragment_authenticator_list">
    </fragment>

</navigation> 
```
