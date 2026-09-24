package sh.mlab.vulnscan

import com.intellij.openapi.progress.ProgressManager
import com.intellij.util.io.HttpRequests
import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URI
import java.net.URLEncoder

// Every request goes through the IDE's HttpRequests, so the user's proxy and
// certificate settings apply. Blocking by design: callers are background tasks,
// and a cancelled task surfaces as ProcessCanceledException, which is never
// caught here.

class HttpFailure(message: String, val kind: ScanErrorKind) : IOException(message)

data class HttpResponse(val status: Int, val body: String, val retryAfter: String?)

object Http {
    fun request(
        url: String,
        method: String = "GET",
        body: ByteArray? = null,
        contentType: String? = null,
        bearer: String? = null,
        timeoutMs: Int,
    ): HttpResponse {
        val builder = if (method == "POST") HttpRequests.post(url, contentType) else HttpRequests.request(url)
        return try {
            builder
                .connectTimeout(timeoutMs)
                .readTimeout(timeoutMs)
                .throwStatusCodeException(false)
                .isReadResponseOnError(true)
                .tuner { c -> if (bearer != null) c.setRequestProperty("Authorization", "Bearer $bearer") }
                .connect { req ->
                    if (body != null) req.write(body)
                    val conn = req.connection as HttpURLConnection
                    val status = conn.responseCode
                    val text = req.readString(ProgressManager.getInstance().progressIndicator)
                    HttpResponse(status, text, conn.getHeaderField("Retry-After"))
                }
        } catch (e: SocketTimeoutException) {
            throw HttpFailure("timed out", ScanErrorKind.TIMEOUT)
        } catch (e: HttpFailure) {
            throw e
        } catch (e: IOException) {
            throw HttpFailure(e.message ?: e.javaClass.simpleName, ScanErrorKind.NETWORK)
        }
    }
}

fun enc(s: String): String = URLEncoder.encode(s, Charsets.UTF_8).replace("+", "%20")

fun hostOf(url: String): String = runCatching { URI(url).host }.getOrNull() ?: url

/** `scheme://host[:port]` of a URL, the `new URL(x).origin` of the TS code. */
fun originOf(url: String): String {
    val u = URI(url)
    return "${u.scheme}://${u.host}${if (u.port != -1) ":${u.port}" else ""}"
}

/** Interruptible sleep for polling loops: wakes early when the task is cancelled. */
fun sleepChecked(ms: Long) {
    val end = System.currentTimeMillis() + ms
    while (System.currentTimeMillis() < end) {
        ProgressManager.checkCanceled()
        Thread.sleep(minOf(100L, end - System.currentTimeMillis()).coerceAtLeast(1))
    }
}
