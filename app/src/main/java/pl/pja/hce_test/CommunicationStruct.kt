package pl.pja.hce_test

data class CommunicationStruct(
    val command: MyHostApduService.Companion.Commands,
    val channel: Array<UByte>
    val
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CommunicationStruct

        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        return data.contentHashCode()
    }
}
