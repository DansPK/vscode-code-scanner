import java.security.MessageDigest
import javax.crypto.Cipher

fun weakHash(data: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(data)

fun weakCipher(): Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
