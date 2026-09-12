const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

/**
 * Executes M3's parser.py on an .eml file and returns parsed JSON.
 *
 * @param {string} filePath Absolute path to the .eml file
 * @returns {Promise<Object>} Parsed email JSON object
 */
exports.parseEmlFile = (filePath) => {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(filePath)) {
      return reject(new Error(`File not found: ${filePath}`));
    }

    const scriptPath = path.resolve(__dirname, "../../parser.py");
    if (!fs.existsSync(scriptPath)) {
      return reject(new Error(`Parser script not found at ${scriptPath}`));
    }

    // Try python3 first if on Linux/Render, or python if on Windows / default
    const pythonCmd = process.env.PYTHON_PATH || (process.platform === "win32" ? "python" : "python3");

    const child = spawn(pythonCmd, [scriptPath, filePath], {
      windowsHide: true,
      timeout: 30000,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", (err) => {
      if (err.code === "ENOENT" && pythonCmd === "python3") {
        // Fallback to "python" if "python3" was not found
        const fallbackChild = spawn("python", [scriptPath, filePath], {
          windowsHide: true,
          timeout: 30000,
        });

        let fbStdout = "";
        let fbStderr = "";

        fallbackChild.stdout.on("data", (d) => (fbStdout += d.toString()));
        fallbackChild.stderr.on("data", (d) => (fbStderr += d.toString()));

        fallbackChild.on("close", (code) => {
          if (code !== 0) {
            return reject(new Error(`Parser failed with code ${code}: ${fbStderr || fbStdout}`));
          }
          try {
            const parsed = JSON.parse(fbStdout.trim());
            resolve(parsed);
          } catch (jsonErr) {
            reject(new Error(`Invalid JSON output from parser: ${fbStdout}`));
          }
        });

        fallbackChild.on("error", (fbErr) => {
          reject(new Error(`Failed to execute Python (${pythonCmd} & python): ${fbErr.message}`));
        });

        return;
      }
      reject(new Error(`Failed to execute Python (${pythonCmd}): ${err.message}`));
    });

    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`Parser failed with code ${code}: ${stderr || stdout}`));
      }

      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch (jsonErr) {
        reject(new Error(`Invalid JSON output from parser: ${stdout}`));
      }
    });
  });
};
