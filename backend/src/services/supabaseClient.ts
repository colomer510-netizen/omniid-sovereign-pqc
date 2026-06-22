import { createClient } from '@supabase/supabase-js';
import * as dotenv from 'dotenv';

dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    console.warn("⚠️ [Supabase] SUPABASE_URL o SUPABASE_SERVICE_KEY no están definidos en .env. Las inserciones fallarán.");
}

// Inicializar Supabase con la Service Key para poder hacer escrituras directas (Issuer Server Mode)
export const supabase = createClient(
    supabaseUrl || '',
    supabaseServiceKey || ''
);
