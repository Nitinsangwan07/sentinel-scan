import app from "./app.js";
import { appConfig } from "./config/env.js";
import { connectDatabase } from "./config/database.js";

async function startServer() {
  try {
    await connectDatabase();

    app.listen(appConfig.port, () => {
      console.log(
        `Sentinel Scan running on http://localhost:${appConfig.port} using ${appConfig.storageMode} storage`,
      );
    });
  } catch (error) {
    console.error("Unable to start Sentinel Scan:", error);
    process.exit(1);
  }
}

startServer();
