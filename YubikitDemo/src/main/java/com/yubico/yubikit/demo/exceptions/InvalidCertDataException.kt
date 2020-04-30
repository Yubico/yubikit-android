package com.yubico.yubikit.demo.exceptions

class InvalidCertDataException(message: String, cause: Throwable?) : Exception(message, cause) {
    constructor(message: String) : this(message, null)
}