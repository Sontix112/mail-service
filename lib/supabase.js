import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

// Ein einziger Admin-Client fuer den gesamten Dienst.
// Service-Role: umgeht RLS. Darf niemals an einen Client ausgeliefert werden.
export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

// Client im Namen eines eingeloggten Nutzers — prueft dessen JWT gegen Supabase.
export function supabaseAsUser(jwt) {
  return createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY,
    { global: { headers: { Authorization: `Bearer ${jwt}` } } }
  );
}
