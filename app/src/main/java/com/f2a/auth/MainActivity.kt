/*
 * F2A-64 · 双算法验证器
 * ────────────────────────────────────────────────────────────
 *  支持两种基于时间的一次性口令：
 *
 *  ① 标准 TOTP（6 位数字，30 秒一变）
 *     counter = floor(unixTime / 30)
 *     hmac    = HMAC-SHA1(secret, counter)
 *     code    = (动态截断(hmac) mod 10^6) → 补零成 6 位
 *
 *  ② F2A-64（64 位字符，60 秒一变）
 *     counter = floor(unixTime / 60)
 *     hmac    = HMAC-SHA512(secret, counter)      → 64 字节
 *     code    = 逐字节映射到 36 进制表 "0-9A-Z"    → 64 字符
 *
 *  两者使用完全相同的密钥（Base32 解码后的字节），只是窗口长度和输出编码不同。
 *  这样同一把密钥既能给只支持 6 位的老系统用，也能给支持 64 位的新系统用。
 * ────────────────────────────────────────────────────────────
 *  MIT License · 作者：棂冕网络
 */
package com.f2a.auth

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

class MainActivity : AppCompatActivity() {

    // ── 配色 ──
    private val BG = 0xFFF5F6F8.toInt()
    private val CARD = Color.WHITE
    private val TXT = 0xFF1A1D24.toInt()
    private val SUB = 0xFF7A8494.toInt()
    private val ACCENT = 0xFF2F6BFF.toInt()
    private val DANGER = 0xFFD93025.toInt()
    private val LINE = 0xFFE6E9EF.toInt()

    private var root: LinearLayout? = null
    private val rows = ArrayList<Pair<Int, TextView>>()
    private var bigCode: TextView? = null
    private var bigName: TextView? = null
    private var curIdx = 0
    private val ui = Handler(Looper.getMainLooper())

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        prefs().edit().putString("device", android.os.Build.MODEL).apply()
        applySecure(secureOn())
        show(0)
        startTick()
    }

    // ══════════════════ 数据层 ══════════════════
    private fun prefs() = getSharedPreferences("f2a64", Context.MODE_PRIVATE)

    private fun vault(): MutableList<JSONObject> {
        val out = ArrayList<JSONObject>()
        try {
            val a = JSONArray(prefs().getString("vault", "[]") ?: "[]")
            for (i in 0 until a.length()) out.add(a.getJSONObject(i))
        } catch (t: Throwable) {}
        return out
    }

    private fun saveVault(l: List<JSONObject>) {
        val a = JSONArray(); l.forEach { a.put(it) }
        prefs().edit().putString("vault", a.toString()).apply()
    }

    // ══════════════════ 算法 ══════════════════

    /** Base32 解码（RFC 4648，接受带空格/连字符/小写） */
    private fun b32(s0: String): ByteArray {
        val s = s0.trim().uppercase().replace(" ", "").replace("-", "").trimEnd('=')
        val alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var buf = 0L; var bits = 0; val out = ArrayList<Byte>()
        for (c in s) {
            val v = alpha.indexOf(c); if (v < 0) continue
            buf = (buf shl 5) or v.toLong(); bits += 5
            if (bits >= 8) { bits -= 8; out.add(((buf shr bits) and 0xFF).toByte()) }
        }
        return out.toByteArray()
    }

    private fun hmac(algo: String, key: ByteArray, msg: ByteArray): ByteArray {
        val m = Mac.getInstance(algo)
        m.init(SecretKeySpec(key, algo))
        return m.doFinal(msg)
    }

    private fun counterBytes(step: Long, off: Int = 0): ByteArray {
        val c = (System.currentTimeMillis() / 1000) / step + off
        return ByteArray(8) { i -> ((c shr (8 * (7 - i))) and 0xFF).toByte() }
    }

    /** ① 标准 TOTP：6 位数字 */
    fun totp(secret: String, step: Long = 30, off: Int = 0): String {
        return try {
            val k = b32(secret); if (k.isEmpty()) return "------"
            val h = hmac("HmacSHA1", k, counterBytes(step, off))
            val o = h[h.size - 1].toInt() and 0x0F
            val bin = ((h[o].toInt() and 0x7F) shl 24) or ((h[o + 1].toInt() and 0xFF) shl 16) or
                      ((h[o + 2].toInt() and 0xFF) shl 8) or (h[o + 3].toInt() and 0xFF)
            String.format("%06d", bin % 1000000)
        } catch (t: Throwable) { "------" }
    }

    /** ② F2A-64：64 位字符（HMAC-SHA512 → 36 进制） */
    fun code64(secret: String, step: Long = 60): String {
        return try {
            val k = b32(secret); if (k.isEmpty()) return ""
            val h = hmac("HmacSHA512", k, counterBytes(step))
            val tab = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            val sb = StringBuilder()
            for (x in h) sb.append(tab[(x.toInt() and 0xFF) % 36])
            sb.toString()          // 正好 64 个字符
        } catch (t: Throwable) { "" }
    }

    /** 按条目类型出码 */
    private fun codeOf(o: JSONObject): String = when (o.optString("t")) {
        "f2a64" -> code64(o.optString("s"), o.optLong("step", 60))
        else    -> totp(o.optString("s"), o.optLong("step", 30))
    }

    // ══════════════════ 防窥屏 ══════════════════
    private fun secureOn() = prefs().getString("secure", "0") == "1"
    private fun applySecure(on: Boolean) {
        try {
            if (on) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } catch (t: Throwable) {}
    }

    // ══════════════════ UI 小工具 ══════════════════
    private fun dp(v: Float) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, resources.displayMetrics).toInt()
    private fun round(fill: Int, r: Int = 14, stroke: Int = 0, sw: Float = 1f): GradientDrawable {
        val g = GradientDrawable(); g.cornerRadius = dp(r.toFloat()).toFloat(); g.setColor(fill)
        if (stroke != 0) g.setStroke(dp(sw), stroke)
        return g
    }
    private fun txt(t: String, sz: Float, c: Int, bold: Boolean = false): TextView {
        val v = TextView(this); v.text = t; v.setTextSize(sz); v.setTextColor(c)
        if (bold) v.setTypeface(v.typeface, Typeface.BOLD)
        return v
    }
    private fun col(): LinearLayout { val l = LinearLayout(this); l.orientation = LinearLayout.VERTICAL; return l }
    private fun lp(w: Int, h: Int, mt: Float = 0f, mb: Float = 0f): LinearLayout.LayoutParams {
        val p = LinearLayout.LayoutParams(w, h); p.topMargin = dp(mt); p.bottomMargin = dp(mb); return p
    }
    private fun btn(label: String, filled: Boolean, h: Float = 54f): TextView {
        val v = txt(label, 16f, if (filled) Color.WHITE else ACCENT, true)
        v.gravity = Gravity.CENTER
        v.background = round(if (filled) ACCENT else CARD, 12, if (filled) 0 else LINE, 1.5f)
        v.isClickable = true
        v.layoutParams = lp(ViewGroup.LayoutParams.MATCH_PARENT, dp(h))
        return v
    }
    private fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_SHORT).show()
    private fun copy(t: String, m: String) {
        (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("f2a", t))
        toast(m)
    }

    private fun show(page: Int) {
        val sc = ScrollView(this); sc.setBackgroundColor(BG)
        val c = col(); c.setPadding(dp(18f), dp(22f), dp(18f), dp(40f))
        sc.addView(c); root = c
        when (page) {
            0 -> pageHome(c)
            1 -> pageCode(c)
            2 -> pageAdd(c)
            3 -> pageSettings(c)
            4 -> pageImport(c)
        }
        setContentView(sc)
    }

    // ══════════════════ 首页 ══════════════════
    private fun pageHome(c: LinearLayout) {
        c.addView(txt("F2A-64", 26f, TXT, true))
        c.addView(txt("双算法验证器 · 6 位 TOTP + 64 位 F2A", 11.5f, SUB), lp(-1, -2, 3f))

        val v = vault()
        if (v.isEmpty()) {
            c.addView(txt("还没有账号\n点下面「添加密钥」开始", 13f, SUB).also {
                it.gravity = Gravity.CENTER; it.setPadding(0, dp(40f), 0, dp(40f))
            }, lp(-1, -2, 22f))
        } else {
            c.addView(txt("我的密钥（${v.size}）", 13f, SUB), lp(-1, -2, 22f, 8f))
            v.forEachIndexed { i, o -> c.addView(rowCard(i, o)) }
        }

        val add = btn("＋ 添加密钥", true, 58f)
        add.setOnClickListener { show(2) }
        c.addView(add, lp(-1, -2, 18f))

        val imp = btn("导入 / 导出", false)
        imp.setOnClickListener { show(4) }
        c.addView(imp, lp(-1, -2, 10f))

        val st = btn("设置", false)
        st.setOnClickListener { show(3) }
        c.addView(st, lp(-1, -2, 10f))
    }

    private fun rowCard(i: Int, o: JSONObject): View {
        val card = col()
        card.background = round(CARD, 14, LINE, 1f)
        card.setPadding(dp(14f), dp(12f), dp(14f), dp(12f))
        card.isClickable = true
        card.layoutParams = lp(-1, -2, 10f)

        val top = LinearLayout(this); top.orientation = LinearLayout.HORIZONTAL
        top.gravity = Gravity.CENTER_VERTICAL
        val nm = txt(o.optString("n", "未命名"), 14.5f, TXT, true)
        top.addView(nm, LinearLayout.LayoutParams(0, -2, 1f))
        val tag = txt(if (o.optString("t") == "f2a64") "64 位" else "6 位", 10.5f,
            if (o.optString("t") == "f2a64") ACCENT else SUB, true)
        tag.background = round(if (o.optString("t") == "f2a64") 0xFFEAF0FF.toInt() else 0xFFF1F3F7.toInt(), 6)
        tag.setPadding(dp(7f), dp(3f), dp(7f), dp(3f))
        top.addView(tag)
        card.addView(top)

        val cd = txt(codeOf(o), 15f, ACCENT, true)
        cd.setPadding(0, dp(8f), 0, 0)
        cd.letterSpacing = 0.04f
        card.addView(cd)
        rows.add(i to cd)

        card.setOnClickListener { curIdx = i; show(1) }
        return card
    }

    // ══════════════════ 单条详情（大码）══════════════════
    private fun pageCode(c: LinearLayout) {
        val v = vault()
        if (curIdx !in v.indices) { show(0); return }
        val o = v[curIdx]
        val is64 = o.optString("t") == "f2a64"

        val back = txt("‹ 返回", 14f, SUB, true)
        back.isClickable = true
        back.setOnClickListener { show(0) }
        c.addView(back)

        bigName = txt(o.optString("n", "未命名") + "   ·   " + (if (is64) "64 位 F2A（60 秒一变）" else "6 位 TOTP（30 秒一变）"), 12.5f, SUB)
        c.addView(bigName, lp(-1, -2, 16f))

        bigCode = txt("……", if (is64) 15f else 42f, ACCENT, true)
        bigCode!!.gravity = Gravity.CENTER
        bigCode!!.letterSpacing = 0.03f
        if (is64) bigCode!!.setLineSpacing(dp(5f).toFloat(), 1f)
        c.addView(bigCode, lp(-1, -2, 10f))

        val cp = btn("复制验证码", true, 56f)
        cp.setOnClickListener { copy(codeOf(o), "已复制") }
        c.addView(cp, lp(-1, -2, 20f))

        val del = btn("删除这个账号", false, 50f)
        del.setTextColor(DANGER)
        del.background = round(CARD, 12, DANGER, 1.5f)
        del.setOnClickListener {
            val l = vault(); l.removeAt(curIdx); saveVault(l); toast("已删除"); show(0)
        }
        c.addView(del, lp(-1, -2, 10f))
    }

    // ══════════════════ 添加密钥 ══════════════════
    private fun field(hint: String): EditText {
        val e = EditText(this)
        e.hint = hint; e.setTextSize(15f)
        e.background = round(0xFFF7F8FA.toInt(), 10, LINE, 1f)
        e.setPadding(dp(14f), dp(13f), dp(14f), dp(13f))
        e.layoutParams = lp(-1, -2, 10f)
        return e
    }

    private fun pageAdd(c: LinearLayout) {
        val back = txt("‹ 返回", 14f, SUB, true)
        back.isClickable = true; back.setOnClickListener { show(0) }
        c.addView(back)
        c.addView(txt("添加密钥", 22f, TXT, true), lp(-1, -2, 14f))

        val fn = field("名称（如：吉安 NAS）")
        c.addView(fn)
        val fs = field("密钥（Base32，如 JBSWY3DPEHPK3PXP）")
        fs.inputType = InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        c.addView(fs)

        c.addView(txt("算法类型", 12.5f, SUB), lp(-1, -2, 14f, 6f))
        val typeRow = LinearLayout(this); typeRow.orientation = LinearLayout.HORIZONTAL
        var is64 = false
        val b6 = btn("6 位 TOTP", true, 48f)
        val b64 = btn("64 位 F2A", false, 48f)
        b6.setOnClickListener {
            is64 = false
            b6.background = round(ACCENT, 12); b6.setTextColor(Color.WHITE)
            b64.background = round(CARD, 12, LINE, 1.5f); b64.setTextColor(ACCENT)
        }
        b64.setOnClickListener {
            is64 = true
            b64.background = round(ACCENT, 12); b64.setTextColor(Color.WHITE)
            b6.background = round(CARD, 12, LINE, 1.5f); b6.setTextColor(ACCENT)
        }
        typeRow.addView(b6, LinearLayout.LayoutParams(0, -2, 1f).also { it.rightMargin = dp(8f) })
        typeRow.addView(b64, LinearLayout.LayoutParams(0, -2, 1f))
        c.addView(typeRow)

        val save = btn("保存", true, 58f)
        save.setOnClickListener {
            val n = fn.text.toString().trim()
            val s = fs.text.toString().trim().uppercase().replace(" ", "").replace("-", "")
            if (n.isEmpty()) { toast("请填名称"); return@setOnClickListener }
            if (s.length < 8) { toast("密钥太短"); return@setOnClickListener }
            val l = vault()
            l.add(JSONObject().put("n", n).put("s", s)
                .put("t", if (is64) "f2a64" else "totp")
                .put("step", if (is64) 60 else 30))
            saveVault(l); toast("已保存"); show(0)
        }
        c.addView(save, lp(-1, -2, 20f))

        val test = txt("提示：6 位算法窗口 30 秒，64 位算法窗口 60 秒；两者用同一把 Base32 密钥。", 11.5f, SUB)
        c.addView(test, lp(-1, -2, 14f))
    }

    // ══════════════════ 设置 ══════════════════
    private fun pageSettings(c: LinearLayout) {
        val back = txt("‹ 返回", 14f, SUB, true)
        back.isClickable = true; back.setOnClickListener { show(0) }
        c.addView(back)
        c.addView(txt("设置", 22f, TXT, true), lp(-1, -2, 14f))

        val on = secureOn()
        c.addView(txt("防窥屏", 14.5f, TXT, true), lp(-1, -2, 16f, 4f))
        c.addView(txt("开启后系统层面禁止截图和录屏（FLAG_SECURE），银行/验证器类 App 的通用做法。", 12f, SUB), lp(-1, -2, 0f, 8f))
        val sw = btn(if (on) "已开启 · 点我关闭" else "已关闭 · 点我开启", on, 52f)
        sw.setOnClickListener {
            val nv = !secureOn()
            prefs().edit().putString("secure", if (nv) "1" else "0").apply()
            applySecure(nv); toast(if (nv) "已开启防窥屏" else "已关闭防窥屏"); show(3)
        }
        c.addView(sw)

        c.addView(txt("关于", 14.5f, TXT, true), lp(-1, -2, 24f, 4f))
        c.addView(txt("F2A-64 v1.0\n双算法：标准 TOTP(6 位/30 秒) + F2A-64(HMAC-SHA512 64 位/60 秒)\nMIT License · 开源免费，无网络权限，密钥只存在本机", 12f, SUB), lp(-1, -2, 0f, 0f))
    }

    // ══════════════════ 导入导出 ══════════════════
    private fun pageImport(c: LinearLayout) {
        val back = txt("‹ 返回", 14f, SUB, true)
        back.isClickable = true; back.setOnClickListener { show(0) }
        c.addView(back)
        c.addView(txt("导入 / 导出", 22f, TXT, true), lp(-1, -2, 14f))

        c.addView(txt("导出（把下面的文本存起来，就是备份）", 12.5f, SUB), lp(-1, -2, 14f, 6f))
        val box = TextView(this)
        box.text = prefs().getString("vault", "[]")
        box.setTextSize(11.5f); box.setTextColor(TXT)
        box.background = round(0xFFF7F8FA.toInt(), 10, LINE, 1f)
        box.setPadding(dp(12f), dp(12f), dp(12f), dp(12f))
        box.setTextIsSelectable(true)
        c.addView(box, lp(-1, -2, 0f, 10f))
        val cp = btn("复制全部", true, 50f)
        cp.setOnClickListener { copy(prefs().getString("vault", "[]"), "已复制，妥善保管") }
        c.addView(cp)

        c.addView(txt("导入（粘贴之前导出的文本）", 12.5f, SUB), lp(-1, -2, 24f, 6f))
        val inp = EditText(this)
        inp.hint = "粘贴 JSON"; inp.setTextSize(12f)
        inp.setMinLines(3)
        inp.background = round(0xFFF7F8FA.toInt(), 10, LINE, 1f)
        inp.setPadding(dp(12f), dp(12f), dp(12f), dp(12f))
        c.addView(inp, lp(-1, -2, 0f, 10f))

        val doImp = btn("导入（合并，不覆盖）", true, 54f)
        doImp.setOnClickListener {
            val t = inp.text.toString().trim()
            if (!t.startsWith("[")) { toast("格式不对"); return@setOnClickListener }
            try {
                val inA = JSONArray(t)
                val cur = vault()
                val names = cur.map { it.optString("n") }.toHashSet()
                var n = 0
                for (i in 0 until inA.length()) {
                    val o = inA.getJSONObject(i)
                    if (!names.contains(o.optString("n"))) { cur.add(o); n++ }
                }
                saveVault(cur); toast("导入 $n 条"); show(0)
            } catch (e: Throwable) { toast("解析失败") }
        }
        c.addView(doImp)
    }

    // ══════════════════ 定时刷新 ══════════════════
    private var ticking = false
    private fun startTick() {
        if (ticking) return
        ticking = true
        ui.post(object : Runnable {
            override fun run() {
                try {
                    val v = vault()
                    rows.forEach { (i, tv) -> if (i < v.size) tv.text = codeOf(v[i]) }
                    if (curIdx in v.indices) {
                        val o = v[curIdx]
                        val is64 = o.optString("t") == "f2a64"
                        val code = codeOf(o)
                        bigCode?.text = if (is64) code.chunked(16).joinToString("\n") else code
                    }
                } catch (t: Throwable) {}
                ui.postDelayed(this, 1000)
            }
        })
    }

    override fun onDestroy() { super.onDestroy(); ui.removeCallbacksAndMessages(null) }
}
