const SUPABASE_URL = "https://nsasjlzlmtjrqxnmutyx.supabase.co";
const SUPABASE_KEY = "sb_publishable_y7c0dI6VHeRReWc7KDUC-Q_boc_q0NA";

const cliente = window.supabase.createClient(
  SUPABASE_URL,
  SUPABASE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: true,
      detectSessionInUrl: false
    }
  }
);

let factorId = null;
const $ = (id) => document.getElementById(id);

function mensaje(texto, error = false) {
  $("mensaje").textContent = texto;
  $("mensaje").style.color = error ? "red" : "green";
}

function pantalla(id) {
  ["paso1", "paso2", "panel"].forEach((s) => {
    $(s).hidden = s !== id;
  });
}

function ocultarQR() {
  $("qr").hidden = true;
  $("qr").removeAttribute("src");
}

async function iniciarSesion() {
  const email = $("correo").value.trim();
  const password = $("password").value;

  if (!email || !password) {
    mensaje("Completa todos los campos.", true);
    return;
  }

  $("btnLogin").disabled = true;

  try {
    const { error } = await cliente.auth.signInWithPassword({
      email,
      password
    });
    if (error) throw error;

    $("password").value = "";
    await prepararSegundoFactor();
  } catch (error) {
    await cliente.auth.signOut({ scope: "local" });
    factorId = null;
    ocultarQR();
    mensaje(error.message, true);
  } finally {
    $("btnLogin").disabled = false;
  }
}

async function prepararSegundoFactor() {
  const { data, error } = await cliente.auth.mfa.listFactors();
  if (error) throw error;

  ocultarQR();
  const factor = data.totp.find((f) => f.status === "verified");

  if (factor) {
    factorId = factor.id;
    $("instrucciones").textContent = "Introduce el código actual.";
  } else {
    for (const f of data.all) {
      if (f.factor_type === "totp" && f.status === "unverified") {
        const r = await cliente.auth.mfa.unenroll({ factorId: f.id });
        if (r.error) throw r.error;
      }
    }

    const r = await cliente.auth.mfa.enroll({
      factorType: "totp",
      friendlyName: "Login2FA"
    });
    if (r.error) throw r.error;

    factorId = r.data.id;
    $("qr").src = r.data.totp.qr_code;
    $("qr").hidden = false;
    $("instrucciones").textContent = "Escanea el QR e introduce el código.";
  }

  pantalla("paso2");
  mensaje("Primer factor correcto. Falta el segundo.");
}

async function verificarCodigo() {
  const code = $("codigo").value.trim();

  if (!/^\d{6}$/.test(code)) {
    mensaje("Introduce seis dígitos.", true);
    return;
  }

  $("btnVerificar").disabled = true;

  try {
    const reto = await cliente.auth.mfa.challenge({ factorId });
    if (reto.error) throw reto.error;

    const r = await cliente.auth.mfa.verify({
      factorId,
      challengeId: reto.data.id,
      code
    });
    if (r.error) throw r.error;

    const nivel = await cliente.auth.mfa.getAuthenticatorAssuranceLevel();
    if (nivel.error) throw nivel.error;

    if (nivel.data.currentLevel !== "aal2") {
      throw new Error("Segundo factor no confirmado.");
    }

    ocultarQR();
    await mostrarDatos();
  } catch (error) {
    mensaje(error.message, true);
  } finally {
    $("btnVerificar").disabled = false;
  }
}

async function mostrarDatos() {
  const { data, error } = await cliente
    .from("informacion_privada")
    .select("mensaje");

  if (error) throw error;
  if (!data.length) throw new Error("No hay información autorizada.");

  $("informacion").textContent = data[0].mensaje;
  $("codigo").value = "";
  pantalla("panel");
  mensaje("Nivel de seguridad: AAL2");
}

async function consultarProteccion() {
  const { data, error } = await cliente
    .from("informacion_privada")
    .select("mensaje");

  if (error) {
    mensaje("Error de consulta: " + error.message, true);
  } else if (data.length === 0) {
    mensaje("Sin registros: falta el segundo factor.", true);
  } else {
    mensaje("Se recibieron registros. Revisa AAL y RLS.", true);
  }
}

async function cerrarSesion() {
  const { error } = await cliente.auth.signOut({ scope: "local" });
  if (error) {
    mensaje(error.message, true);
    return;
  }

  factorId = null;
  ["correo", "password", "codigo"].forEach((id) => {
    $(id).value = "";
  });
  $("informacion").textContent = "";
  ocultarQR();
  pantalla("paso1");
  mensaje("Sesión cerrada correctamente.");
}