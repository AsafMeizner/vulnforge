/// <reference types="vite/client" />

// import.meta.env augmentation. Keeping this as a plain triple-slash
// directive so every .ts/.tsx file under src/ picks up the standard
// vite types (ImportMetaEnv, ImportMeta.env, BASE_URL, MODE, DEV, PROD).
//
// Added when we needed `${import.meta.env.BASE_URL}brand/...` to avoid
// file:// absolute-path breakage for static assets in the packaged app.
