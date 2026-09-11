# 🚀 M2 Backend - Step-by-Step Guide

This guide covers exactly what you need to do right now to test the backend, and what your next steps are for the SIH project.

---

## 🟢 PHASE 1: Test What We Just Built

Your backend and MongoDB connection are now fully working. Let's test the flow.

### Step 1: Start the server
Open your VS Code terminal and run:
```bash
npm run dev
```
*(Note: If `npm` gives a red error, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` first, hit Y, then try again).*

You should see:
```text
✅ MongoDB connected
🚀 Server running on http://localhost:5000
```

### Step 2: Open Postman (or Thunder Client)
We are going to send a fake "parsed email" to your backend to make sure it saves to MongoDB.

1. **Method:** `POST`
2. **URL:** `http://localhost:5000/api/emails`
3. **Headers:** Add a new header with Key: `Content-Type` and Value: `application/json`
4. **Body:** Select `Raw` and paste everything from the `test/sample-email.json` file inside your project.
5. **Click Send!**

✅ **Expected Result:** A `201 Created` response saying "Email stored successfully", along with a newly generated MongoDB `_id`.

### Step 3: Retrieve the Email
1. Copy the `_id` from the response in Step 2.
2. Change the **Method** to `GET`.
3. Change the **URL** to: `http://localhost:5000/api/emails/<PASTE_ID_HERE>`
4. **Click Send!**

✅ **Expected Result:** You will get the full email data back from MongoDB.

*(Check MongoDB Atlas or Compass and you will see an `emails` collection has been created with your data!)*

---

## 🟡 PHASE 2: Connect with M3 (The Parser)

Right now, we used a "fake" sample email (`sample-email.json`). The real goal is to get the JSON from the person working on **M3**.

### Step 4: Get M3's actual JSON format
1. Ask the team member working on **M3**: *"Hey, can you send me a sample of the exact JSON your parser generates?"*
2. Compare their JSON with your `src/models/Email.js` schema. 
3. **If their JSON has different field names** (e.g., they use `sender_email` instead of `sender.address`), let me know and we will update the Mongoose schema to match their exact output.

### Step 5: Integration
Once M3 is ready, their code will automatically send a `POST` request to your `http://localhost:5000/api/emails` API every time an email is uploaded.

---

## 🔵 PHASE 3: Build the Rest of the Database (M1, M4, M5, M6)

Once the Email saving part is 100% working with M3, we need to build the other collections for the rest of the team.

When you are ready, just tell me: **"Let's build Phase 3"** and we will add:

1. **IOCs Collection (`/api/iocs`)**: For **M4** to investigate IPs, Domains, and URLs.
2. **Threat Analyses Collection (`/api/analyses`)**: For **M1 & M5** to save their forensic AI reports and threat scores.
3. **Cases Collection (`/api/cases`)**: For **M6** to display security incidents on the frontend dashboard.
