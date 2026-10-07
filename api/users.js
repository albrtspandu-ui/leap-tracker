/* ============================================================
   /api/users  —  pembuatan dan pengelolaan akun oleh admin
   ------------------------------------------------------------
   Fungsi ini berjalan di server Vercel, bukan di browser, karena
   memakai service_role key yang boleh melakukan apa saja pada
   database. Kunci itu tidak boleh pernah masuk ke index.html.

   Pemanggil wajib mengirim access token Supabase miliknya.
   Fungsi memeriksa bahwa pemilik token itu benar-benar admin
   sebelum mengerjakan apa pun.

   Environment variable yang dibutuhkan di Vercel:
     SUPABASE_URL                 https://xxxx.supabase.co
     SUPABASE_SERVICE_ROLE_KEY    kunci service_role dari Supabase
   ============================================================ */

const LOGIN_DOMAIN = 'leap.mds.local';
const URL_BASE = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SERVICE  = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

function svc(path, init) {
  return fetch(URL_BASE + path, Object.assign({}, init, {
    headers: Object.assign({
      'apikey': SERVICE,
      'Authorization': 'Bearer ' + SERVICE,
      'Content-Type': 'application/json'
    }, (init && init.headers) || {})
  }));
}

async function readJson(res) {
  const text = await res.text();
  try { return text ? JSON.parse(text) : null; } catch (e) { return { raw: text }; }
}

/* pastikan pemanggilnya admin; kembalikan id-nya */
async function requireAdmin(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return { error: 'Tidak ada token. Silakan masuk ulang.', status: 401 };

  const who = await fetch(URL_BASE + '/auth/v1/user', {
    headers: { 'apikey': SERVICE, 'Authorization': 'Bearer ' + token }
  });
  if (!who.ok) return { error: 'Sesi tidak berlaku. Silakan masuk ulang.', status: 401 };
  const user = await readJson(who);
  if (!user || !user.id) return { error: 'Sesi tidak berlaku.', status: 401 };

  const pr = await svc('/rest/v1/profiles?select=role&id=eq.' + user.id);
  const rows = await readJson(pr);
  if (!Array.isArray(rows) || !rows[0] || rows[0].role !== 'admin') {
    return { error: 'Hanya admin program yang boleh mengelola akun.', status: 403 };
  }
  return { id: user.id };
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Gunakan metode POST.' });
  }
  if (!URL_BASE || !SERVICE) {
    return res.status(500).json({
      error: 'Environment variable SUPABASE_URL atau SUPABASE_SERVICE_ROLE_KEY belum diisi di Vercel.'
    });
  }

  const gate = await requireAdmin(req);
  if (gate.error) return res.status(gate.status).json({ error: gate.error });

  const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  const action = body.action;

  try {
    /* ---------- buat akun baru ---------- */
    if (action === 'create') {
      const username = String(body.username || '').trim().toLowerCase();
      const password = String(body.password || '');
      const role = body.role;

      if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
        return res.status(400).json({ error: 'Nama pengguna hanya boleh huruf kecil, angka, titik, garis bawah, atau strip, 3 sampai 30 karakter.' });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: 'Kata sandi minimal 6 karakter.' });
      }
      if (role !== 'mentor' && role !== 'peserta') {
        return res.status(400).json({ error: 'Peran harus mentor atau peserta.' });
      }
      if (!String(body.name || '').trim()) {
        return res.status(400).json({ error: 'Nama lengkap wajib diisi.' });
      }

      const email = username + '@' + LOGIN_DOMAIN;

      const created = await svc('/auth/v1/admin/users', {
        method: 'POST',
        body: JSON.stringify({ email: email, password: password, email_confirm: true })
      });
      const cu = await readJson(created);
      if (!created.ok) {
        const msg = (cu && (cu.msg || cu.message || cu.error_description)) || 'Gagal membuat akun.';
        const dup = /already|exists|registered/i.test(msg);
        return res.status(400).json({ error: dup ? ('Nama pengguna "' + username + '" sudah dipakai.') : msg });
      }

      const profile = {
        id: cu.id,
        role: role,
        name: String(body.name).trim(),
        email: String(body.email || '').trim() || null,
        store: role === 'peserta' ? (String(body.store || '').trim() || null) : null,
        region: role === 'mentor' ? (String(body.region || '').trim() || null) : null,
        mentor_id: role === 'peserta' ? (body.mentor_id || null) : null
      };
      const ins = await svc('/rest/v1/profiles', {
        method: 'POST',
        headers: { 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify(profile)
      });
      if (!ins.ok) {
        /* profil gagal dibuat: batalkan akunnya supaya tidak ada akun yatim */
        await svc('/auth/v1/admin/users/' + cu.id, { method: 'DELETE' });
        const e = await readJson(ins);
        return res.status(400).json({ error: (e && (e.message || e.hint)) || 'Gagal menyimpan profil.' });
      }
      return res.status(200).json({ ok: true, id: cu.id, username: username });
    }

    /* ---------- ganti kata sandi ---------- */
    if (action === 'password') {
      const id = String(body.id || '');
      const password = String(body.password || '');
      if (!id) return res.status(400).json({ error: 'Id pengguna tidak ada.' });
      if (password.length < 6) return res.status(400).json({ error: 'Kata sandi minimal 6 karakter.' });

      const upd = await svc('/auth/v1/admin/users/' + id, {
        method: 'PUT',
        body: JSON.stringify({ password: password })
      });
      if (!upd.ok) {
        const e = await readJson(upd);
        return res.status(400).json({ error: (e && (e.msg || e.message)) || 'Gagal mengganti kata sandi.' });
      }
      return res.status(200).json({ ok: true });
    }

    /* ---------- hapus akun ---------- */
    if (action === 'delete') {
      const id = String(body.id || '');
      if (!id) return res.status(400).json({ error: 'Id pengguna tidak ada.' });
      if (id === gate.id) return res.status(400).json({ error: 'Anda tidak bisa menghapus akun Anda sendiri.' });

      const del = await svc('/auth/v1/admin/users/' + id, { method: 'DELETE' });
      if (!del.ok) {
        const e = await readJson(del);
        return res.status(400).json({ error: (e && (e.msg || e.message)) || 'Gagal menghapus akun.' });
      }
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: 'Aksi tidak dikenali.' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String((e && e.message) || e) });
  }
};
