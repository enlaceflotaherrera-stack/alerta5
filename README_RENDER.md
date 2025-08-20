
# Despliegue en Render.com (paso a paso corto)

1) Sube este repo a **GitHub** (puedes usar la interfaz web de GitHub → "Add file" → "Upload files").
2) En **Render.com** → New → **Blueprint** → conecta tu repo y acepta.
3) En la vista del servicio, ve a **Environment** y pega:
   - `MONGO_URI` → el enlace de MongoDB Atlas
   - `JWT_SECRET` → una palabra secreta
   - (Opcional) `VAPID_PUBLIC` y `VAPID_PRIVATE` si quieres Push
4) Haz **Redeploy**. Cuando salga el check verde, Render mostrará tu **URL pública**.
