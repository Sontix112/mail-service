import nodemailer from "nodemailer";
import { supabaseAdmin } from "./supabase.js";
import { decryptPassword } from "./crypto.js";

// Baut einen Transporter aus einem mail_accounts-Datensatz.
export async function transporterForAccount(account) {
  const password = await decryptPassword(
    account.password_encrypted,
    process.env.MAIL_CREDENTIALS_SECRET
  );

  return nodemailer.createTransport({
    host: account.smtp_host,
    port: account.smtp_port,
    secure: account.smtp_secure,
    auth: { user: account.username, pass: password },
  });
}

export function fromHeader(account) {
  return account.email
    ? `${account.display_name || ""} <${account.email}>`
    : account.username;
}

// Verschickt eine Mail ueber das Standardkonto eines Inhabers.
// Wird vom Portal genutzt, wo kein Konto mitgegeben wird.
export async function sendMailAsUser(userId, to, subject, text) {
  const { data: account, error } = await supabaseAdmin
    .from("mail_accounts")
    .select("*")
    .eq("user_id", userId)
    .eq("is_active", true)
    .order("is_default", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error || !account) throw new Error("Kein aktives Mailkonto gefunden");

  const transporter = await transporterForAccount(account);

  return transporter.sendMail({
    from: fromHeader(account),
    to,
    subject,
    text,
  });
}
