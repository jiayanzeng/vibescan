const supabaseUrl = "https://abcdefghijklmnopqrst.supabase.co";
const supabaseKey = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

export async function loadProfiles() {
  return fetch(`${supabaseUrl}/rest/v1/profiles?select=*`, {
    headers: { apikey: supabaseKey },
  });
}
