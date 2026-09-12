const fs = require("fs");

async function uploadEmails() {
  const file = fs.readFileSync(
    "./m3_samples/parsed_emails_50.json",
    "utf-8"
  );

  const emails = JSON.parse(file);

  for (const email of emails) {
    const response = await fetch("http://localhost:5000/api/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(email)
    });

    const result = await response.json();

    if (response.ok) {
      console.log(`✅ Uploaded email: ${result.data ? result.data.email_id : 'Unknown ID'}`);
    } else {
      console.log("❌ Failed to upload:", result);
    }
  }

  console.log("Finished uploading emails.");
}

uploadEmails().catch(console.error);
