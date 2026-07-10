const supabaseUrl = "https://abcdefghijklmnopqrst.supabase.co";
const supabaseKey = "sb_publishable_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

export default function Page() {
  return <main data-url={supabaseUrl} data-key={supabaseKey}>Client app</main>;
}
