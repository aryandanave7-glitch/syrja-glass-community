const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const crypto = require('crypto');
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb"); // Import MongoDB client & ObjectId


function log(...args) {
    console.log('[Syrja-Server-Log]', ...args);
}
// --- NEW: Utility Function for Logging ---
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
// --- END NEW ---


// --- START: MongoDB Setup ---
// --- START: MongoDB Setup ---
// IMPORTANT: Use Environment Variable in Production (See Step 4 later)
// For now, paste your connection string here during testing, BUT REMEMBER TO CHANGE IT
const mongoUri = process.env.MONGODB_URI || "mongodb+srv://syrjaServerUser:YOUR_SAVED_PASSWORD@yourclustername.mongodb.net/?retryWrites=true&w=majority"; // Replace placeholder or use env var

if (!mongoUri) {
    console.error("🚨 FATAL ERROR: MONGODB_URI environment variable is not set and no fallback provided.");
    process.exit(1);
}

// Create a MongoClient with options
const mongoClient = new MongoClient(mongoUri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: false,
    deprecationErrors: true,
  }
});

let db; // To hold the database connection
let idsCollection; // To hold the collection reference
let offlineMessagesCollection;
let groupsCollection; // For group metadata
let groupOfflineMessagesCollection; // For offline group messages
let channelsCollection; // For channel info
let channelUpdatesCollection; // For channel messages

async function connectToMongo() {
  try {
    await mongoClient.connect();
    db = mongoClient.db("syrjaAppDb"); // Choose a database name
    idsCollection = db.collection("syrjaIds"); // Choose a collection name

    // --- TTL Index for Temporary IDs ---
    await idsCollection.createIndex({ "expireAt": 1 }, { expireAfterSeconds: 0 });
    
    // --- NEW: Setup for Offline Messages ---
    offlineMessagesCollection = db.collection("offlineMessages");

    // 1. TTL Index for 14-day expiry (on 'expireAt' field)
    await offlineMessagesCollection.createIndex({ "expireAt": 1 }, { expireAfterSeconds: 0 });

    // 2. Index for finding messages FOR a recipient
    await offlineMessagesCollection.createIndex({ recipientPubKey: 1 });

    // 3. Index for calculating a sender's quota usage
    await offlineMessagesCollection.createIndex({ senderPubKey: 1 });

    console.log("✅ Offline messages collection and indexes are ready.");
    // --- END NEW ---
    // --- NEW: Setup for Channels ---
    channelsCollection = db.collection("channels");
    channelUpdatesCollection = db.collection("channelUpdates");

    // 1. Create a UNIQUE index on ownerPubKey for the 'channels' collection
    // This automatically enforces your "1 channel per user" rule.
    await channelsCollection.createIndex({ ownerPubKey: 1 }, { unique: true });

    // 2. Create a TEXT index on name/description for searching
    await channelsCollection.createIndex({ channelName: "text", description: "text" });

    // 3. Create a TTL index for 24-hour message expiry
    // This is your 24-hour deletion rule. MongoDB handles it automatically.
    // 86400 seconds = 24 hours
    await channelUpdatesCollection.createIndex({ "createdAt": 1 }, { expireAfterSeconds: 86400 });

    // 4. Create an index on channelId for fast message lookups
    await channelUpdatesCollection.createIndex({ channelId: 1 });

    console.log("✅ Channels collections and indexes are ready.");

    // server.js (Added after the "Channels collections" log)
    
    // --- NEW: Setup for Permanent Channel Posts (Task 1.1) ---
    permanentPostsCollection = db.collection("permanentPosts");
    
    // 1. Index for finding all permanent posts for a channel
    await permanentPostsCollection.createIndex({ channelId: 1 });
    // 2. Index for finding the owner (for quota checks)
    await permanentPostsCollection.createIndex({ ownerPubKey: 1 });
    
    console.log("✅ Permanent posts collection and indexes are ready.");
    // --- END NEW ---

    // server.js (Added after the "Permanent posts collection" log)
    
    // --- NEW: Setup for Auto-Cached Channel Posts (Task 1.1) ---
    autoCachedPostsCollection = db.collection("autoCachedPosts");

    // 1. Index for finding all cached posts for a channel
    await autoCachedPostsCollection.createIndex({ channelId: 1 });
    // 2. Index for finding the oldest posts to delete (FIFO)
    await autoCachedPostsCollection.createIndex({ channelId: 1, createdAt: 1 });
    // 3. Add TTL index (24h) as a fallback safety measure
    // This ensures posts are still deleted if the FIFO logic fails
    await autoCachedPostsCollection.createIndex({ "createdAt": 1 }, { expireAfterSeconds: 86400 });

    console.log("✅ Auto-cached posts collection and indexes are ready.");

    // --- NEW: Setup for Groups (Phase 1) ---
    groupsCollection = db.collection("groups");
    groupOfflineMessagesCollection = db.collection("groupOfflineMessages");

    // 1. Index for finding groups by member
    await groupsCollection.createIndex({ "members": 1 });

    // 2. Index for finding offline group messages for a specific user
    await groupOfflineMessagesCollection.createIndex({ recipientPubKey: 1 });
    // 3. Index for finding messages for a specific group (for cleanup, etc.)
    await groupOfflineMessagesCollection.createIndex({ groupID: 1 });
    // 4. TTL index for group messages (e.g., 14 days, same as 1-to-1)
    await groupOfflineMessagesCollection.createIndex({ "expireAt": 1 }, { expireAfterSeconds: 0 });

    console.log("✅ Groups collections and indexes are ready.");
    // --- END NEW: Setup for Groups ---
    // --- END NEW ---
    // --- END NEW ---
    console.log("✅ Connected successfully to MongoDB Atlas");
  } catch (err) {
    console.error("❌ Failed to connect to MongoDB Atlas", err);
    process.exit(1); // Exit if DB connection fails on startup
  }
}
// --- END: MongoDB Setup ---

/**
 * Verifies an ECDSA (P-256) signature.
 * @param {string} pubKeyB64 - The SPKI public key in Base64.
 * @param {string} signatureB64 - The Base64 encoded signature.
 * @param {string} data - The original string data that was signed.
 * @returns {Promise<boolean>} - True if the signature is valid, false otherwise.
 */
// In server.js

// In server.js

// In server.js

async function verifySignature(pubKeyB64, signatureB64, data) {
  // --- [Syrja-Debug-V5] ---
  console.log("--- [Syrja-Debug-V5] INSIDE FINAL VERIFY SIGNATURE FUNCTION ---"); 
 
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(pubKeyB64, 'base64'),
      format: 'der',
      type: 'spki'
    });

    const verify = crypto.createVerify('SHA-256');
    // Keep this fix: Explicitly use 'utf8' to match the client
    verify.update(data, 'utf8'); 
    verify.end();

    const signature = Buffer.from(signatureB64, 'base64');
   
    console.log(`[Syrja-Debug-V5] Verifying data (first 50): ${data.slice(0, 50)}...`);

    // --- THIS IS THE FINAL FIX ---
    // We must provide the signature *format* here.
    // The key is an object specifying the DSA encoding format.
    const result = verify.verify(
      { key: key, dsaEncoding: 'ieee-p1363' }, 
      signature
    ); 
    // --- END FINAL FIX ---
   
    console.log(`[Syrja-Debug-V5] SIGNATURE VERIFICATION RESULT: ${result}`);

    return result; 
 
  } catch (err) {
    console.error("[Syrja-Debug-V5] Signature verification CRASHED:", err.message);
    return false;
  }
}

// Simple word lists for more memorable IDs
const ADJECTIVES = ["alpha", "beta", "gamma", "delta", "zeta", "nova", "comet", "solar", "lunar", "star"];
const NOUNS = ["fox", "wolf", "hawk", "lion", "tiger", "bear", "crane", "iris", "rose", "maple"];

const app = express();

// --- NEW: Explicit CORS Configuration ---
const corsOptions = {
  origin: "*", // Allow all origins (you can restrict this later)
  methods: "GET,POST,DELETE,OPTIONS", // Allow these methods
  // --- THIS IS THE FIX ---
  // Change from a string to an array and add your custom headers
  allowedHeaders: [
    'Content-Type',
    'X-Syrja-Sig',
    'X-Syrja-Ts'
  ]
  // --- END FIX ---
};

// Enable pre-flight requests for all routes
app.options('*', cors(corsOptions)); 
// Use the main CORS configuration
app.use(cors(corsOptions));
// --- END NEW ---

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});
// --- START: Syrja ID Directory Service (v2) ---

app.use(express.json({ limit: '2mb' })); // Middleware to parse JSON bodies
app.use(cors());       // CORS Middleware

// Initialize node-persist storage


// Endpoint to claim a new Syrja ID
// Endpoint to claim a new Syrja ID (MODIFIED for MongoDB)
app.post("/claim-id", async (req, res) => {
    const { customId, fullInviteCode, persistence, privacy, pubKey } = req.body; // Added privacy

    // Added privacy check in condition
    if (!customId || !fullInviteCode || !persistence || !privacy || !pubKey) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    try {
        // Check if this public key already owns a DIFFERENT ID using MongoDB findOne
        const existingUserEntry = await idsCollection.findOne({ pubKey: pubKey });
        // Use _id from MongoDB document
        if (existingUserEntry && existingUserEntry._id !== customId) {
            return res.status(409).json({ error: "You already own a different ID. Please delete it before claiming a new one." });
        }

        // Check if the requested ID is taken by someone else using MongoDB findOne
        const existingIdEntry = await idsCollection.findOne({ _id: customId });
        if (existingIdEntry && existingIdEntry.pubKey !== pubKey) {
            return res.status(409).json({ error: "ID already taken" });
        }

        // Decode the invite code to extract profile details
        let decodedProfile;
        let statusText = null; // Default to null
        let updateText = null;
        let updateColor = null;
        try {
            decodedProfile = JSON.parse(Buffer.from(fullInviteCode, 'base64').toString('utf8'));
            statusText = decodedProfile.statusText || null; // Extract status text, default to null if missing
            updateText = decodedProfile.updateText || null;
            updateColor = decodedProfile.updateColor || null;
            ecdhPubKey = decodedProfile.ecdhPubKey || null; // <-- NEW
            console.log(`[Claim/Update ID: ${customId}] Decoded Profile - Status Text: '${statusText}'`);
            
        } catch (e) {
            console.error(`[Claim/Update ID: ${customId}] Failed to decode fullInviteCode:`, e);
            // Decide how to handle this - maybe reject the request or proceed without status?
            // For now, we'll proceed with statusText as null.
        }

        // Prepare the document to insert/update for MongoDB
        const syrjaDoc = {
            _id: customId,
            code: fullInviteCode, // Still store raw code for potential fallback/debugging
            pubKey: pubKey,
            permanent: persistence === 'permanent',
            privacy: privacy,
            updatedAt: new Date(),
            // --- NEW: Store extracted fields ---
            name: decodedProfile?.name || null, // Store name
            avatar: decodedProfile?.avatar || null, // Store avatar (URL or null)
            statusText: statusText, // Store status text (string or null)
            ecdhPubKey: ecdhPubKey,
            updateText: updateText,
            updateColor: updateColor,
            updateTimestamp: updateText ? new Date() : null 
            // --- END NEW ---
        };

        // Set expiration only for temporary IDs
        if (persistence === 'temporary') {
            syrjaDoc.expireAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        } else {
            // Ensure expireAt field is absent or explicitly null for permanent IDs
            // $unset below handles removal if it exists, so no need to set null here if updating.
        }

        // Use replaceOne with upsert:true to insert or replace the document
        await idsCollection.replaceOne(
            { _id: customId },
            syrjaDoc,
            { upsert: true }
        );

        // If making permanent or updating a permanent record, ensure expireAt field is removed
        if (persistence === 'permanent') {
             await idsCollection.updateOne({ _id: customId }, { $unset: { expireAt: "" } });
        }
        // Updated console log
        console.log(`✅ ID Claimed/Updated: ${customId} (Permanent: ${syrjaDoc.permanent}, Privacy: ${privacy})`);
        res.json({ success: true, id: customId });

    } catch (err) {
        console.error("claim-id error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});
// Endpoint to get an invite code from a Syrja ID (for adding contacts)
// Endpoint to get an invite code from a Syrja ID (MODIFIED for MongoDB)
// Endpoint to get an invite code from a Syrja ID (MODIFIED for MongoDB + Block Check)
app.get("/get-invite/:id", async (req, res) => {
    const fullId = `syrja/${req.params.id}`;
    const searcherPubKey = req.query.searcherPubKey; // Get searcher's PubKey from query param

    // --- NEW: Require searcherPubKey ---
    if (!searcherPubKey) {
        return res.status(400).json({ error: "Missing searcherPubKey query parameter" });
    }
    // --- END NEW ---

    try {
        const item = await idsCollection.findOne({ _id: fullId });

        // --- MODIFIED: Check if essential fields exist ---
        if (item && item.pubKey && item.name) {
            // --- Block Check ---
            if (item.blockedSearchers && item.blockedSearchers.includes(searcherPubKey)) {
                console.log(`🚫 Search denied: ${fullId} blocked searcher ${searcherPubKey.slice(0,12)}...`);
                return res.status(404).json({ error: "ID not found" });
            }

            // --- Privacy Check ---
            if (item.privacy === 'private') {
                console.log(`🔒 Attempt to resolve private Syrja ID denied: ${fullId}`);
                return res.status(403).json({ error: "This ID is private" });
            }

            // --- NEW: Reconstruct the invite code payload ---
            const invitePayload = {
                name: item.name,
                key: item.pubKey,
                // Assuming server URL needs to be included - get it from config/env or omit if not needed
                server: process.env.SERVER_URL || '', // Example: Get server URL if needed
                avatar: item.avatar || null,
                statusText: item.statusText || null, // Include status text
                ecdhPubKey: item.ecdhPubKey || null, // <-- NEW
                updateText: item.updateText || null,
                updateColor: item.updateColor || null,
                updateTimestamp: item.updateTimestamp || null
                
            };
            // Remove null/undefined values to keep payload clean
            Object.keys(invitePayload).forEach(key => invitePayload[key] == null && delete invitePayload[key]);

            const reconstructedInviteCode = Buffer.from(JSON.stringify(invitePayload)).toString('base64');
            // --- END NEW ---

            console.log(`➡️ Resolved Syrja ID: ${fullId} (Privacy: ${item.privacy || 'public'}, Status: '${invitePayload.statusText || ''}', Update: '${invitePayload.updateText || ''}')`);
            // --- MODIFIED: Send reconstructed code ---
            res.json({ fullInviteCode: reconstructedInviteCode });
        } else {
            console.log(`❓ Failed to resolve Syrja ID (not found, expired, or missing data): ${fullId}`);
            res.status(404).json({ error: "ID not found, has expired, or profile data incomplete" });
        }
    } catch (err) {
        console.error("get-invite error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});

// Endpoint to find a user's current ID by their public key
// Endpoint to find a user's current ID by their public key (MODIFIED for MongoDB)
app.get("/get-id-by-pubkey/:pubkey", async (req, res) => {
    const pubkey = req.params.pubkey;
    try {
        // Use findOne to search by the pubKey field
        const item = await idsCollection.findOne({ pubKey: pubkey });

        if (item) {
            // Found a match, return the document's _id and other details
            console.log(`🔎 Found ID for pubkey ${pubkey.slice(0,12)}... -> ${item._id}`);
            // Include privacy in the response
            res.json({ id: item._id, permanent: item.permanent, privacy: item.privacy });
        } else {
            // No document found matching the public key
            console.log(`🔎 No ID found for pubkey ${pubkey.slice(0,12)}...`);
            res.status(404).json({ error: "No ID found for this public key" });
        }
    } catch (err) {
        // Handle potential database errors
        console.error("get-id-by-pubkey error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});
// Endpoint to delete an ID, authenticated by public key
// Endpoint to delete an ID, authenticated by public key (MODIFIED for MongoDB)
app.post("/delete-id", async (req, res) => {
    const { pubKey } = req.body;
    if (!pubKey) return res.status(400).json({ error: "Public key is required" });

    try {
        // Use deleteOne to remove the document matching the public key
        const result = await idsCollection.deleteOne({ pubKey: pubKey });

        // Check if a document was actually deleted
        if (result.deletedCount > 0) {
            console.log(`🗑️ Deleted Syrja ID for pubKey: ${pubKey.slice(0,12)}...`);
            res.json({ success: true });
        } else {
            // If deletedCount is 0, no document matched the pubKey
            console.log(`🗑️ No Syrja ID found for pubKey ${pubKey.slice(0,12)}... to delete.`);
            res.json({ success: true, message: "No ID found to delete" });
        }
    } catch (err) {
        // Handle potential database errors
        console.error("delete-id error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});

// Endpoint to block a user from searching for you
app.post("/block-user", async (req, res) => {
    const { blockerPubKey, targetIdentifier } = req.body;

    if (!blockerPubKey || !targetIdentifier) {
        return res.status(400).json({ error: "Missing required fields (blockerPubKey, targetIdentifier)" });
    }

    // --- Resolve targetIdentifier to targetPubKey ---
    // This is a simplified resolution. You might need more robust logic
    // depending on whether the client sends an ID or PubKey.
    // Let's assume for now the client resolves and sends the target's PubKey.
    const targetPubKey = targetIdentifier; // Assuming client sends resolved PubKey for simplicity here.
    // TODO: Add logic here if you need the server to resolve a syrja/ ID to a PubKey.
    // ---

    try {
        const blockerDoc = await idsCollection.findOne({ pubKey: blockerPubKey });

        if (!blockerDoc) {
            return res.status(404).json({ error: "Your Syrja ID profile not found." });
        }

        // Use $addToSet to add the targetPubKey to the blocker's blockedSearchers array
        // $addToSet automatically handles duplicates.
        const updateResult = await idsCollection.updateOne(
            { pubKey: blockerPubKey },
            { $addToSet: { blockedSearchers: targetPubKey } }
        );

        if (updateResult.modifiedCount > 0 || updateResult.matchedCount > 0) {
             console.log(`🛡️ User ${blockerPubKey.slice(0,12)}... blocked ${targetPubKey.slice(0,12)}... from searching.`);
             res.json({ success: true, message: "User blocked successfully." });
        } else {
             // This case should ideally not happen if the blockerDoc was found,
             // but included for completeness.
             res.status(404).json({ error: "Could not find your profile to update." });
        }

    } catch (err) {
        console.error("block-user error:", err);
        res.status(500).json({ error: "Database operation failed during block." });
    }
});

// Endpoint to unblock a user, allowing them to search for you again
app.post("/unblock-user", async (req, res) => {
    const { unblockerPubKey, targetIdentifier } = req.body;

    if (!unblockerPubKey || !targetIdentifier) {
        return res.status(400).json({ error: "Missing required fields (unblockerPubKey, targetIdentifier)" });
    }

    // --- Resolve targetIdentifier to targetPubKey ---
    // Assuming client sends resolved PubKey for simplicity here.
    const targetPubKey = targetIdentifier;
    // TODO: Add server-side resolution if needed.
    // ---

    try {
        const unblockerDoc = await idsCollection.findOne({ pubKey: unblockerPubKey });

        if (!unblockerDoc) {
            return res.status(404).json({ error: "Your Syrja ID profile not found." });
        }

        // Use $pull to remove the targetPubKey from the blockedSearchers array
        const updateResult = await idsCollection.updateOne(
            { pubKey: unblockerPubKey },
            { $pull: { blockedSearchers: targetPubKey } }
        );

        // Check if modification happened or if the document was matched
        if (updateResult.modifiedCount > 0) {
            console.log(`🔓 User ${unblockerPubKey.slice(0,12)}... unblocked ${targetPubKey.slice(0,12)}...`);
            res.json({ success: true, message: "User unblocked successfully." });
        } else if (updateResult.matchedCount > 0) {
            // Matched but didn't modify (target wasn't in the array)
            res.json({ success: true, message: "User was not in the block list." });
        }
         else {
            res.status(404).json({ error: "Could not find your profile to update." });
        }

    } catch (err) {
        console.error("unblock-user error:", err);
        res.status(500).json({ error: "Database operation failed during unblock." });
    }
});

// --- START: Offline Message Relay Service ---
const USER_QUOTA_BYTES = 1 * 1024 * 1024; // 1MB

app.post("/relay-message", async (req, res) => {
    const { senderPubKey, recipientPubKey, encryptedPayload } = req.body;

    if (!senderPubKey || !recipientPubKey || !encryptedPayload) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        // 1. Check payload size (encryptedPayload is base64 string)
        const payloadSizeBytes = Buffer.from(encryptedPayload, 'base64').length;
        if (payloadSizeBytes > USER_QUOTA_BYTES) {
             return res.status(413).json({ error: `Payload (${payloadSizeBytes} bytes) exceeds total user quota (${USER_QUOTA_BYTES} bytes).` });
        }

        // 2. Check user's current quota usage
        const userMessages = await offlineMessagesCollection.find({ senderPubKey }).toArray();
        let currentUsage = 0;
        userMessages.forEach(msg => {
            currentUsage += msg.sizeBytes || 0; // Use stored size
        });

        if (currentUsage + payloadSizeBytes > USER_QUOTA_BYTES) {
            return res.status(413).json({ error: `Quota exceeded. Current usage: ${currentUsage} bytes. This message: ${payloadSizeBytes} bytes. Limit: ${USER_QUOTA_BYTES} bytes.` });
        }

        // 3. Store the message
        const messageDoc = {
            senderPubKey,
            recipientPubKey,
            encryptedPayload,
            sizeBytes: payloadSizeBytes,
            createdAt: new Date(),
            expireAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14-day TTL
        };

        const insertResult = await offlineMessagesCollection.insertOne(messageDoc);

        console.log(`📦 Relayed message stored: ${insertResult.insertedId} from ${senderPubKey.slice(0,10)}... to ${recipientPubKey.slice(0,10)}...`);
        res.status(201).json({ success: true, messageId: insertResult.insertedId.toString(), size: payloadSizeBytes });

    } catch (err) {
        console.error("relay-message error:", err);
        res.status(500).json({ error: "Database operation failed." });
    }
});

// Endpoint for sender to view their relayed messages and quota
app.get("/my-relayed-messages/:senderPubKey", async (req, res) => {
    const { senderPubKey } = req.params;
    if (!senderPubKey) return res.status(400).json({ error: "Missing sender public key." });

    try {
        const messages = await offlineMessagesCollection.find(
            { senderPubKey },
            { projection: { _id: 1, recipientPubKey: 1, sizeBytes: 1, createdAt: 1 } } // Only send safe metadata
        ).toArray();

        let currentUsage = 0;
        messages.forEach(msg => { currentUsage += msg.sizeBytes; });

        res.json({
            quotaUsed: currentUsage,
            quotaLimit: USER_QUOTA_BYTES,
            messages: messages
        });
    } catch (err) {
        console.error("my-relayed-messages error:", err);
        res.status(500).json({ error: "Database operation failed." });
    }
});

// Endpoint for sender to delete a message they relayed
app.delete("/delete-relayed-message/:messageId", async (req, res) => {
    const { messageId } = req.params;
    const { senderPubKey } = req.body; // Sender must prove ownership

    if (!senderPubKey) return res.status(400).json({ error: "Missing sender public key for auth." });

    try {
        // Need to use MongoDB's ObjectId for lookup
        const { ObjectId } = require("mongodb");
        const _id = new ObjectId(messageId);

        const deleteResult = await offlineMessagesCollection.deleteOne({
            _id: _id,
            senderPubKey: senderPubKey // CRITICAL: Ensure only the sender can delete
        });

        if (deleteResult.deletedCount === 1) {
            console.log(`🗑️ Sender ${senderPubKey.slice(0,10)}... deleted relayed message ${messageId}`);
            res.json({ success: true });
        } else {
            res.status(404).json({ error: "Message not found or you are not the owner." });
        }
    } catch (err) {
        console.error("delete-relayed-message error:", err);
        res.status(500).json({ error: "Database operation failed or invalid ID." });
    }
});

// --- END: Offline Message Relay Service ---



// --- END: Syrja ID Directory Service (v2) ---
// --- START: Channels API Endpoints ---

/**
 * [AUTHENTICATED] Create a new channel.
 * Enforces "1 channel per user" via a unique index on ownerPubKey.
 */
// In server.js

app.post("/channels/create", async (req, res) => {
    // 1. Receive the payloadString and signature
    const { payloadString, signature } = req.body;
    
    if (!payloadString || !signature) {
        return res.status(400).json({ error: "Missing required payloadString or signature." });
    }

    // 2. This is the *exact* string the client signed
    const dataToVerify = payloadString;
    
    // 3. Parse the string to get the payload object
    let payload;
    try {
        payload = JSON.parse(payloadString);
    } catch (e) {
        return res.status(400).json({ error: "Invalid payload format." });
    }

    // 4. Check for fields *inside* the parsed object
    if (!payload.pubKey || !payload.channelName) {
       return res.status(400).json({ error: "Payload missing pubKey or channelName." });
    }
    
    console.log("--- SERVER IS VERIFYING ---");
    console.log("SERVER PAYLOAD STRING:", dataToVerify);
    console.log("SERVER SIGNATURE (first 30):", signature.slice(0, 30) + "...");
    console.log("SERVER PUBKEY (first 30):", payload.pubKey.slice(0, 30) + "...");

    // 5. Verify the signature against the *original string*
    const isOwner = await verifySignature(payload.pubKey, signature, dataToVerify);
    if (!isOwner) {
        console.log("[Syrja-Debug-V5] VERIFICATION FAILED. Sending original error.");
        return res.status(403).json({ error: "Invalid signature. Cannot create channel." });
    }

    // 6. Proceed to insert into DB
    try {
        const newChannel = {
            ownerPubKey: payload.pubKey,
            channelName: payload.channelName,
            description: payload.description || "",
            avatar: payload.avatar || null,
            followerCount: 0,
            createdAt: new Date(),
            permanentStorageUsed: 0, // Start with 0 bytes used
            permanentStorageQuota: 2 * 1024 * 1024, // Set 2MB quota
            autoCacheQuota: 0,
            storageMode: "manual" // <-- NEW: Default all new channels to manual mode
            // --- END NEW ---
        };
        
        await channelsCollection.insertOne(newChannel);

        // Use the parsed payload for logging
        console.log(`✅ Channel Created: ${payload.channelName} by ${payload.pubKey.slice(0, 10)}...`);
        
        res.status(201).json(newChannel); 

    } catch (err) {
        if (err.code === 11000) { 
            return res.status(409).json({ error: "You can only create one channel per account." });
        }
        console.error("Channel creation error:", err);
        res.status(500).json({ error: "Server error creating channel." });
    }
});

// server.js (Added after the /channels/create endpoint)

/**
 * [AUTHENTICATED] Pin a post to make it permanent.
 * Copies a 24-hour post to the permanent collection.
 */
app.post("/channels/pin-post", async (req, res) => {
    const { postId, pubKey, signature } = req.body;
    if (!postId || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields (postId, pubKey, signature)." });
    }

    try {
        // 1. Verify the signature (Owner signed the *postId* to confirm pinning)
        const isAuthentic = await verifySignature(pubKey, signature, postId);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid pin signature." });
        }

        // 2. Find the channel to get its quota and verify ownership
        // 2. Find the channel to get its quota and verify ownership
        const channel = await channelsCollection.findOne({ ownerPubKey: pubKey });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found for this public key." });
        }

        // NEW RULE: Check storage mode
        if (channel.storageMode !== "manual") {
            return res.status(403).json({ error: "Cannot pin posts while in Auto-Cache mode." });
        }
        
        // 3. Find the original 24-hour post
        
        // 3. Find the original 24-hour post
        const postToPin = await channelUpdatesCollection.findOne({ _id: new ObjectId(postId) });
        if (!postToPin) {
            // Check if it's already pinned
            const alreadyPinned = await permanentPostsCollection.findOne({ _id: new ObjectId(postId) });
            if (alreadyPinned) return res.status(409).json({ error: "Post is already pinned." });
            
            return res.status(404).json({ error: "Original post not found (it may have expired)." });
        }
        
        // 4. Verify the post is from the owner's channel
        if (postToPin.channelId.toString() !== channel._id.toString()) {
            return res.status(403).json({ error: "Post does not belong to this channel." });
        }

        // --- AS PER OUR PLAN: We will add media checks here later ---
        // For now, we just check the size.

        // 5. Check the quota
        const postSize = Buffer.byteLength(postToPin.content, 'utf8');
        const quota = channel.permanentStorageQuota || (2 * 1024 * 1024); // Default 2MB
        const used = channel.permanentStorageUsed || 0;

        if (used + postSize > quota) {
            return res.status(413).json({ error: `Quota exceeded. This post is ${formatBytes(postSize)}, you have ${formatBytes(quota - used)} remaining.` });
        }

        // 6. Copy the post to the permanent collection
        // We use the *same _id* so we can easily find/merge it
        const permanentPost = {
            _id: postToPin._id, // Use the same ID as the original post
            channelId: postToPin.channelId,
            ownerPubKey: pubKey, // Add owner pubkey for indexing
            content: postToPin.content,
            signature: postToPin.signature,
            createdAt: postToPin.createdAt
        };
        await permanentPostsCollection.insertOne(permanentPost);

        // 7. Update the channel's used storage
        await channelsCollection.updateOne(
            { _id: channel._id },
            { $inc: { permanentStorageUsed: postSize } }
        );
        
        console.log(`📌 Post Pinned: ${postId} for channel ${channel.channelName}. Quota used: ${formatBytes(used + postSize)}`);
        res.status(201).json({ success: true, message: "Post pinned." });

    } catch (err) {
        if (err.code === 11000) { // Duplicate key error
            return res.status(409).json({ error: "Post is already pinned." });
        }
        console.error("Channel pin error:", err);
        res.status(500).json({ error: "Server error pinning post." });
    }
});

// server.js (Added after the /channels/pin-post endpoint)

/**
 * [AUTHENTICATED] Unpin a post to remove it from permanent storage.
 * Deletes a post from the permanent collection and frees up quota.
 */
app.post("/channels/unpin-post", async (req, res) => {
    const { postId, pubKey, signature } = req.body;
    if (!postId || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields (postId, pubKey, signature)." });
    }

    try {
        // 1. Verify the signature (Owner signed the *postId* to confirm unpinning)
        const isAuthentic = await verifySignature(pubKey, signature, postId);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid unpin signature." });
        }

        // 2. Find the channel to verify ownership
        const channel = await channelsCollection.findOne({ ownerPubKey: pubKey });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found for this public key." });
        }

        // NEW RULE: Check storage mode
        if (channel.storageMode !== "manual") {
            // Silently succeed, as the post isn't permanent anyway
            return res.status(200).json({ success: true, message: "Post not permanent." });
        }

        // 3. Find the permanent post to be deleted

        // 3. Find the permanent post to be deleted
        const postToUnpin = await permanentPostsCollection.findOne({
            _id: new ObjectId(postId),
            ownerPubKey: pubKey // Ensure it's their post
        });

        if (!postToUnpin) {
            return res.status(404).json({ error: "Permanent post not found (or not owned by you)." });
        }
        
        // 4. Calculate the size to be freed
        const postSize = Buffer.byteLength(postToUnpin.content, 'utf8');

        // 5. Delete the post from the permanent collection
        await permanentPostsCollection.deleteOne({ _id: postToUnpin._id });

        // 6. Update (decrement) the channel's used storage
        // We use $max to ensure the quota never drops below 0
        await channelsCollection.updateOne(
            { _id: channel._id },
            { $inc: { permanentStorageUsed: -postSize } }
        );
        // Follow-up query to fix any potential negative numbers (e.g., if quota was reset)
        await channelsCollection.updateOne(
            { _id: channel._id, permanentStorageUsed: { $lt: 0 } },
            { $set: { permanentStorageUsed: 0 } }
        );
        
        console.log(`... Post Unpinned: ${postId} from channel ${channel.channelName}. Freed: ${formatBytes(postSize)}`);
        res.status(200).json({ success: true, message: "Post unpinned." });

    } catch (err) {
        console.error("Channel unpin error:", err);
        res.status(500).json({ error: "Server error unpinning post." });
    }
});

// server.js (Added after the /channels/unpin-post endpoint)

/**
 * [AUTHENTICATED] Get all permanent posts for the owner's channel.
 * Used for the "Manage Storage" panel.
 */
app.get("/channels/permanent-posts/:pubKey", async (req, res) => {
    const { pubKey } = req.params;
    
    // We use a header for the signature to avoid query string issues
    const signature = req.headers['x-syrja-sig'];
    const timestamp = req.headers['x-syrja-ts'];

    if (!pubKey || !signature || !timestamp) {
        return res.status(400).json({ error: "Missing required fields (pubKey, signature, timestamp)." });
    }

    // Anti-replay: Check if timestamp is recent (e.g., within 30 seconds)
    if (Math.abs(Date.now() - parseInt(timestamp, 10)) > 30000) {
        return res.status(408).json({ error: "Request timestamp is too old." });
    }

    try {
        // 1. Verify the signature (Owner signed their own pubKey + timestamp)
        const dataToVerify = `${pubKey}${timestamp}`;
        const isAuthentic = await verifySignature(pubKey, signature, dataToVerify);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        // 2. Find all permanent posts for this owner
        const posts = await permanentPostsCollection.find({
            ownerPubKey: pubKey
        }).sort({ createdAt: -1 }).toArray(); // Sort newest first

        res.status(200).json(posts);

    } catch (err) {
        console.error("Get permanent posts error:", err);
        res.status(500).json({ error: "Server error getting posts." });
    }
});

// server.js (Added after the /channels/permanent-posts endpoint)

/**
 * [AUTHENTICATED] Set the auto-cache quota for a channel.
 */
app.post("/channels/set-auto-cache", async (req, res) => {
    // 1. Get the signed payload
    const { payloadString, signature } = req.body;
    if (!payloadString || !signature) {
        return res.status(400).json({ error: "Missing required payloadString or signature." });
    }

    // 2. Parse the payload
    let payload;
    try {
        payload = JSON.parse(payloadString);
    } catch (e) {
        return res.status(400).json({ error: "Invalid payload format." });
    }

    const { pubKey, autoCacheQuota } = payload;
    // autoCacheQuota can be 0, so we check if it's undefined
    if (!pubKey || autoCacheQuota === undefined) {
       return res.status(400).json({ error: "Payload missing pubKey or autoCacheQuota." });
    }
    
    // 3. Validate the new quota
    const newQuota = parseInt(autoCacheQuota, 10);
    const MAX_AUTO_CACHE = 1 * 1024 * 1024; // 1MB
    if (isNaN(newQuota) || newQuota < 0 || newQuota > MAX_AUTO_CACHE) {
        return res.status(400).json({ error: `Invalid quota. Must be a number between 0 and ${MAX_AUTO_CACHE}.`});
    }

    try {
        // 4. Verify the signature (Owner signed the payload string to confirm)
        const isAuthentic = await verifySignature(pubKey, signature, payloadString);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }
        
        // 5. Find the channel and update its quota
        const updateResult = await channelsCollection.updateOne(
            { ownerPubKey: pubKey },
            { $set: { autoCacheQuota: newQuota } }
        );
        
        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ error: "Channel not found for this public key." });
        }
        
        console.log(`... Auto-Cache Quota Set: ${formatBytes(newQuota)} for owner ${pubKey.slice(0, 10)}...`);
        res.status(200).json({ success: true, newQuota: newQuota });

    } catch (err) {
        console.error("Set auto-cache error:", err);
        res.status(500).json({ error: "Server error setting auto-cache." });
    }
});


/**
 * [AUTHENTICATED] Post a new update to a channel.
 */
app.post("/channels/post", async (req, res) => {
    const { channelId, content, pubKey, signature } = req.body;
    if (!channelId || !content || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        // 1. Find the channel
        const channel = await channelsCollection.findOne({ ownerPubKey: pubKey });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found for this owner." });
        }
        
        // Now, verify the channelId from the client matches the one we found
        if (channel._id.toString() !== channelId) {
             return res.status(403).json({ error: "Channel ID mismatch." });
        }

        // 2. Verify the poster is the owner
        if (channel.ownerPubKey !== pubKey) {
            return res.status(403).json({ error: "You are not the owner of this channel." });
        }

        // 3. Verify the signature (owner signed the content)
        const isAuthentic = await verifySignature(pubKey, signature, content);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid message signature." });
        }

        // 4. Store the public message
        const newUpdate = {
            channelId: new ObjectId(channelId),
            content,
            signature, // Store the signature for client-side verification
            createdAt: new Date()
            // The TTL index will handle deletion in 24h
        };
        await channelUpdatesCollection.insertOne(newUpdate);
        // server.js (Added after the channelUpdatesCollection.insertOne line)

        // --- NEW: Auto-Cache (FIFO) Logic (Task 1.4) ---
        if (channel.storageMode === 'auto' && channel.autoCacheQuota && channel.autoCacheQuota > 0) {
            try {
                const postSize = Buffer.byteLength(content, 'utf8');

                // 1. Copy the post to the auto-cache collection
                const cachedPost = {
                    _id: newUpdate._id, // Use the same ID
                    channelId: newUpdate.channelId,
                    content: newUpdate.content,
                    signature: newUpdate.signature,
                    createdAt: newUpdate.createdAt,
                    size: postSize // Store the size for quota math
                };
                await autoCachedPostsCollection.insertOne(cachedPost);

                // 2. Check and enforce the quota
                const allCachedPosts = await autoCachedPostsCollection.find(
                    { channelId: channel._id },
                    { projection: { createdAt: 1, size: 1 } }
                ).sort({ createdAt: 1 }).toArray(); // Get all posts, oldest first

                let totalSize = allCachedPosts.reduce((sum, post) => sum + (post.size || 0), 0);

                if (totalSize > channel.autoCacheQuota) {
                    log(`... Auto-Cache: Quota exceeded (${formatBytes(totalSize)} / ${formatBytes(channel.autoCacheQuota)}). Pruning...`);
                    const postsToDelete = [];
                    // Keep deleting oldest posts until we are under quota
                    for (const post of allCachedPosts) {
                        if (totalSize <= channel.autoCacheQuota) {
                            break; // We're under quota
                        }
                        postsToDelete.push(post._id);
                        totalSize -= post.size;
                    }
                    
                    if (postsToDelete.length > 0) {
                        await autoCachedPostsCollection.deleteMany({ _id: { $in: postsToDelete } });
                        log(`... Auto-Cache: Pruned ${postsToDelete.length} old posts.`);
                    }
                }
                
            } catch (cacheErr) {
                // Log the error but don't fail the whole post
                console.error("Auto-cache logic failed:", cacheErr.message);
            }
        }
        // --- END NEW ---

        console.log(`📢 New post in channel: ${channel.channelName}`);
        res.status(201).json({ success: true, message: newUpdate });

    } catch (err) {
        console.error("Channel post error:", err);
        res.status(500).json({ error: "Server error posting update." });
    }
});
// server.js (REPLACING existing function at line 935)
/**
 * [ANONYMOUS] Get top channels (by follower count)
 */
app.get("/channels/discover/top", async (req, res) => {
    try {
        // --- MODIFIED: Allow client to specify a limit, default to 10 ---
        const limit = parseInt(req.query.limit) || 10;
        // --- END MODIFIED ---

        const topChannels = await channelsCollection
            .find()
            .sort({ followerCount: -1 }) // Sort by followers
            .limit(limit) 
            .toArray();
        res.json(topChannels);
    } catch (err) {
        res.status(500).json({ error: "Server error." });
    }
});

/**
 * [ANONYMOUS] Search for channels by name/description
 */
app.get("/channels/discover/search", async (req, res) => {
    const query = req.query.q;
    if (!query) {
        return res.status(400).json({ error: "Missing search query 'q'." });
    }

    try {
        const results = await channelsCollection
            .find({ $text: { $search: query } })
            .toArray();
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: "Server error." });
    }
});
// server.js (REPLACING the /channels/fetch endpoint)
// server.js (REPLACING the /channels/fetch endpoint)
/**
 * [ANONYMOUS] Fetch new messages for followed channels.
 * Fetches 24-hour TTL, permanent-pinned, and auto-cached posts.
 */
app.post("/channels/fetch", async (req, res) => {
    const { channels } = req.body; // e.g., [{ id: "...", since: "..." }]
    if (!Array.isArray(channels) || channels.length === 0) {
        return res.json([]);
    }

    try {
        // --- 1. Build Queries for ALL THREE Collections ---
        
        // Query 1: Get 24-hour posts created *since* the last check
        const ttlQueries = channels.map(c => ({
            channelId: new ObjectId(c.id),
            createdAt: { $gt: new Date(c.since) }
        }));
        
        // Query 2 & 3: Get ALL permanent and auto-cached posts for these channels
        const channelIds = channels.map(c => new ObjectId(c.id));
        const permanentQuery = {
            channelId: { $in: channelIds }
        };

        // --- 2. Execute Queries in Parallel ---
        const [ttlMessages, permanentMessages, autoCachedMessages] = await Promise.all([
            channelUpdatesCollection.find(ttlQueries.length ? { $or: ttlQueries } : {}).toArray(),
            permanentPostsCollection.find(permanentQuery).toArray(),
            autoCachedPostsCollection.find(permanentQuery).toArray() // <-- NEW
        ]);

        // --- 3. Merge and De-duplicate ---
        // We use a Map to ensure posts are not duplicated.
        // The order here is important.
        const messageMap = new Map();
        
        // Add 24-hour messages first (least important)
        for (const msg of ttlMessages) {
            messageMap.set(msg._id.toString(), msg);
        }
        
        // Add auto-cached messages (overwrites 24-hour)
        for (const msg of autoCachedMessages) {
            messageMap.set(msg._id.toString(), msg);
        }
        
        // Add permanent-pinned messages last (overwrites everything)
        for (const msg of permanentMessages) {
            messageMap.set(msg._id.toString(), msg);
        }

        // Convert the map back to an array
        const allNewMessages = Array.from(messageMap.values());
        
        // Sort the final merged list by creation date
        allNewMessages.sort((a, b) => a.createdAt - b.createdAt);

        res.json(allNewMessages);

    } catch (err) {
        console.error("Channel fetch error:", err);
        res.status(500).json({ error: "Server error fetching updates." });
    }
});
/**
 * [ANONYMOUS] Anonymously increment a channel's follower count.
 */
app.post("/channels/follow/:id", async (req, res) => {
    try {
        await channelsCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $inc: { followerCount: 1 } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Server error." });
    }
});

/**
 * [ANONYMOUS] Anonymously decrement a channel's follower count.
 */
app.post("/channels/unfollow/:id", async (req, res) => {
    try {
        await channelsCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $inc: { followerCount: -1 } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Server error." });
    }
});

// --- END: Channels API Endpoints ---
// server.js (Added after the /unfollow endpoint)

/**
 * [AUTHENTICATED] Delete a post from a channel.
 * Verifies ownership before deleting.
 */
app.post("/channels/delete-post", async (req, res) => {
    // We sign the postId to prove ownership and prevent replay attacks
    const { postId, pubKey, signature } = req.body;
    
    if (!postId || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields (postId, pubKey, signature)." });
    }

    try {
        // 1. Find the post to get the channelId
        const post = await channelUpdatesCollection.findOne({ _id: new ObjectId(postId) });
        if (!post) {
            return res.status(404).json({ error: "Post not found." });
        }

        // 2. Find the channel to verify the owner
        const channel = await channelsCollection.findOne({ _id: new ObjectId(post.channelId) });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found." });
        }

        // 3. Verify the poster is the owner
        if (channel.ownerPubKey !== pubKey) {
            return res.status(403).json({ error: "You are not the owner of this channel." });
        }

        // 4. Verify the signature (owner signed the *postId* to confirm deletion)
        // This proves they are actively deleting *this specific post*
        const isAuthentic = await verifySignature(pubKey, signature, postId);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid deletion signature." });
        }

        // 5. Delete the post
        await channelUpdatesCollection.deleteOne({ _id: new ObjectId(postId) });

        console.log(`🗑️ Post Deleted: ${postId} from channel ${channel.channelName}`);
        res.status(200).json({ success: true, message: "Post deleted." });

    } catch (err) {
        console.error("Channel post deletion error:", err);
        res.status(500).json({ error: "Server error deleting post." });
    }
});
// server.js (Added after the /channels/delete-post endpoint)

/**
 * [ANONYMOUS] Get public metadata for a single channel.
 * Used for populating the channel info panel.
 */
app.get("/channels/meta/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const channel = await channelsCollection.findOne(
            { _id: new ObjectId(id) },
            {
                // Projection: Only return these specific, safe fields
                projection: {
                    channelName: 1,
                    description: 1,
                    avatar: 1,
                    followerCount: 1,
                    // --- NEW: Add quota fields ---
                    ownerPubKey: 1, // Need this to check ownership on client
                    permanentStorageUsed: 1,
                    permanentStorageQuota: 1,
                    autoCacheQuota: 1,
                    storageMode: 1 // <-- ADD THIS LINE
                    // --- END NEW ---
                }
            }
        );

        if (!channel) {
            return res.status(404).json({ error: "Channel not found." });
        }

        // 'channel' object will only contain _id, channelName, description, avatar, followerCount
        res.status(200).json(channel);

    } catch (err) {
        console.error("Get channel meta error:", err);
        res.status(500).json({ error: "Server error or invalid ID." });
    }
});
// server.js (Added after the /channels/meta/:id endpoint)

/**
 * [AUTHENTICATED] Update a channel's metadata (avatar, description).
 * Verifies ownership before updating.
 */
app.post("/channels/update-meta", async (req, res) => {
    // 1. Get the signed payload
    const { payloadString, signature } = req.body;
    if (!payloadString || !signature) {
        return res.status(400).json({ error: "Missing required payloadString or signature." });
    }

    // 2. Parse the payload
    let payload;
    try {
        payload = JSON.parse(payloadString);
    } catch (e) {
        return res.status(400).json({ error: "Invalid payload format." });
    }

    const { channelId, pubKey, description, avatar } = payload;
    if (!channelId || !pubKey) {
       return res.status(400).json({ error: "Payload missing channelId or pubKey." });
    }

    try {
        // 3. Find the channel
        const channel = await channelsCollection.findOne({ _id: new ObjectId(channelId) });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found." });
        }

        // 4. Verify the poster is the owner
        if (channel.ownerPubKey !== pubKey) {
            return res.status(403).json({ error: "You are not the owner of this channel." });
        }

        // 5. Verify the signature (owner signed the *entire payload string*)
        const isAuthentic = await verifySignature(pubKey, signature, payloadString);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        // 6. Build the update document (only update fields that were provided)
        const fieldsToUpdate = {};
        if (description !== undefined) {
            fieldsToUpdate.description = description;
        }
        if (avatar !== undefined) {
            fieldsToUpdate.avatar = avatar; // This can be a data URL or null
        }

        // 7. Perform the update
        if (Object.keys(fieldsToUpdate).length > 0) {
            await channelsCollection.updateOne(
                { _id: new ObjectId(channelId) },
                { $set: fieldsToUpdate }
            );
            console.log(`✅ Channel Meta Updated: ${channel.channelName} by ${pubKey.slice(0, 10)}...`);
        } else {
            console.log(`ℹ️ Channel Meta: No fields to update for ${channel.channelName}.`);
        }

        res.status(200).json({ success: true, message: "Channel updated." });

    } catch (err) {
        console.error("Channel meta update error:", err);
        res.status(500).json({ error: "Server error updating channel." });
    }
});

// server.js (Added after the /channels/update-meta endpoint)

/**
 * [AUTHENTICATED] Delete an entire channel.
 * Verifies ownership, then deletes the channel and all its posts.
 */
app.post("/channels/delete", async (req, res) => {
    // 1. Get the signed payload
    const { channelId, pubKey, signature } = req.body;
    if (!channelId || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields (channelId, pubKey, signature)." });
    }

    try {
        // 2. Find the channel to verify the owner
        const channel = await channelsCollection.findOne({ _id: new ObjectId(channelId) });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found." });
        }

        // 3. Verify the poster is the owner
        if (channel.ownerPubKey !== pubKey) {
            return res.status(403).json({ error: "You are not the owner of this channel." });
        }

        // 4. Verify the signature (owner signed the *channelId* to confirm deletion)
        const isAuthentic = await verifySignature(pubKey, signature, channelId);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid deletion signature." });
        }

        // 5. Delete the channel document
        await channelsCollection.deleteOne({ _id: new ObjectId(channelId) });
        
        // 6. Delete all posts associated with that channel
        const deleteResult = await channelUpdatesCollection.deleteMany({ channelId: new ObjectId(channelId) });

        console.log(`🗑️ CHANNEL DELETED: ${channel.channelName} by ${pubKey.slice(0, 10)}...`);
        console.log(`   - Deleted ${deleteResult.deletedCount} associated posts.`);
        res.status(200).json({ success: true, message: "Channel and all posts deleted." });

    } catch (err) {
        console.error("Channel deletion error:", err);
        res.status(500).json({ error: "Server error deleting channel." });
    }
});

// --- NEW: "My Data" Privacy Endpoints ---

/**
 * [AUTHENTICATED] Fetches all data associated with a user's public key.
 */
app.get("/my-data/:pubKey", async (req, res) => {
    const { pubKey } = req.params;
    const signature = req.headers['x-syrja-sig'];
    const timestamp = req.headers['x-syrja-ts'];

    if (!pubKey || !signature || !timestamp) {
        return res.status(400).json({ error: "Missing required fields (pubKey, signature, timestamp)." });
    }
    // Anti-replay: Check if timestamp is recent (e.g., within 30 seconds)
    if (Math.abs(Date.now() - parseInt(timestamp, 10)) > 30000) {
        return res.status(408).json({ error: "Request timestamp is too old." });
    }

    try {
        // Verify the signature (Owner signed their own pubKey + timestamp)
        const dataToVerify = `${pubKey}${timestamp}`;
        const isAuthentic = await verifySignature(pubKey, signature, dataToVerify);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        log(`... Fetching all data for ${pubKey.slice(0, 10)}...`);

        // 1. Get all data in parallel
        const [
            profile,
            offlineMessages,
            channel,
        ] = await Promise.all([
            idsCollection.findOne({ pubKey: pubKey }),
            offlineMessagesCollection.find({ senderPubKey: pubKey }).toArray(),
            channelsCollection.findOne({ ownerPubKey: pubKey }),
        ]);

        let permanentPosts = [];
        let autoCachedPosts = [];
        let channelPosts24h = [];

        if (channel) {
            // 2. If channel exists, get its posts
            const [perm, auto, ttl] = await Promise.all([
                permanentPostsCollection.find({ channelId: channel._id }).toArray(),
                autoCachedPostsCollection.find({ channelId: channel._id }).toArray(),
                channelUpdatesCollection.find({ channelId: channel._id }).toArray(),
            ]);
            permanentPosts = perm;
            autoCachedPosts = auto;
            channelPosts24h = ttl;
        }

        // 3. Bundle the data
        const allData = {
            profile: profile || null,
            offlineMessages: offlineMessages,
            channel: channel || null,
            channelPosts: {
                permanent: permanentPosts,
                autoCached: autoCachedPosts,
                ttl24Hour: channelPosts24h,
            }
        };

        res.status(200).json(allData);

    } catch (err) {
        console.error("Get /my-data error:", err);
        res.status(500).json({ error: "Server error fetching data." });
    }
});

/**
 * [AUTHENTICATED] Deletes all data associated with a user's public key.
 */
app.delete("/my-data/:pubKey", async (req, res) => {
    const { pubKey } = req.params;
    const signature = req.headers['x-syrja-sig'];
    const timestamp = req.headers['x-syrja-ts'];

    if (!pubKey || !signature || !timestamp) {
        return res.status(400).json({ error: "Missing required fields." });
    }
    if (Math.abs(Date.now() - parseInt(timestamp, 10)) > 30000) {
        return res.status(408).json({ error: "Request timestamp is too old." });
    }

    try {
        const dataToVerify = `${pubKey}${timestamp}`;
        const isAuthentic = await verifySignature(pubKey, signature, dataToVerify);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        log(`... DELETING all data for ${pubKey.slice(0, 10)}...`);

        // 1. Find the user's channel first to get the ID
        const channel = await channelsCollection.findOne({ ownerPubKey: pubKey }, { projection: { _id: 1 } });

        // 2. Start all deletions in parallel
        const deletePromises = [
            idsCollection.deleteOne({ pubKey: pubKey }),
            offlineMessagesCollection.deleteMany({ senderPubKey: pubKey }),
            channelsCollection.deleteOne({ ownerPubKey: pubKey }),
        ];

        if (channel) {
            log(`... Deleting associated channel posts for channel ${channel._id}...`);
            deletePromises.push(
                permanentPostsCollection.deleteMany({ channelId: channel._id })
            );
            deletePromises.push(
                autoCachedPostsCollection.deleteMany({ channelId: channel._id })
            );
            deletePromises.push(
                channelUpdatesCollection.deleteMany({ channelId: channel._id })
            );
        }

        await Promise.all(deletePromises);

        log(`... All data for ${pubKey.slice(0, 10)} has been permanently deleted.`);
        res.status(200).json({ success: true, message: "All user data deleted." });

    } catch (err) {
        console.error("Delete /my-data error:", err);
        res.status(500).json({ error: "Server error deleting data." });
    }
});

/**
 * [AUTHENTICATED] Set the storage mode (manual/auto) for a channel.
 * This is a destructive action that clears the other mode's data.
 */
app.post("/channels/set-storage-mode", async (req, res) => {
    const { channelId, pubKey, signature, newMode } = req.body;

    if (!channelId || !pubKey || !signature || !newMode) {
        return res.status(400).json({ error: "Missing required fields." });
    }
    if (newMode !== 'auto' && newMode !== 'manual') {
        return res.status(400).json({ error: "Invalid mode." });
    }

    try {
        // 1. Verify signature
        const dataToVerify = channelId + newMode; // Client signs this
        const isAuthentic = await verifySignature(pubKey, signature, dataToVerify);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        // 2. Find channel and verify owner
        const channel = await channelsCollection.findOne({ _id: new ObjectId(channelId), ownerPubKey: pubKey });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found or you are not the owner." });
        }

        // 3. Perform the destructive action
        if (newMode === 'auto') {
            // Switching TO Auto: Delete all permanent posts
            const deleteResult = await permanentPostsCollection.deleteMany({ channelId: channel._id });
            // Update channel document
            await channelsCollection.updateOne(
                { _id: channel._id },
                { $set: { storageMode: "auto", permanentStorageUsed: 0 } }
            );
            log(`... Channel ${channel.channelName} switched to AUTO mode. Deleted ${deleteResult.deletedCount} permanent posts.`);
        
        } else { // newMode === 'manual'
            // Switching TO Manual: Delete all auto-cached posts
            const deleteResult = await autoCachedPostsCollection.deleteMany({ channelId: channel._id });
            // Update channel document
            await channelsCollection.updateOne(
                { _id: channel._id },
                { $set: { storageMode: "manual", autoCacheQuota: 0 } } // Also reset auto-cache quota
            );
            log(`... Channel ${channel.channelName} switched to MANUAL mode. Deleted ${deleteResult.deletedCount} auto-cached posts.`);
        }

        res.status(200).json({ success: true, newMode: newMode });

    } catch (err) {
        console.error("Set storage mode error:", err);
        res.status(500).json({ error: "Server error switching mode." });
    }
});

// --- START: Group Chat API Endpoints (Phase 1) ---

/**
 * [AUTHENTICATED] Create a new group.
 * The request only contains unencrypted metadata.
 * The client is responsible for encrypting and distributing the GroupKey.
 */
app.post("/group/create", async (req, res) => {
    const { groupName, groupAvatar, members, ownerPubKey, signature } = req.body;

    if (!groupName || !Array.isArray(members) || members.length === 0 || !ownerPubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields (groupName, members, ownerPubKey, signature)." });
    }

    // Verify the signature (owner signed the groupName + all member PubKeys sorted)
    const membersString = [...members].sort().join(',');
    const dataToVerify = `${groupName}${membersString}${ownerPubKey}`;

    const isOwner = await verifySignature(ownerPubKey, signature, dataToVerify);
    if (!isOwner) {
        return res.status(403).json({ error: "Invalid signature. Cannot create group." });
    }

    // Ensure the owner is also in the member list
    if (!members.includes(ownerPubKey)) {
        members.push(ownerPubKey);
    }

    try {
        const newGroup = {
            groupName: groupName,
            groupAvatar: groupAvatar || null,
            owner: ownerPubKey,
            admins: [ownerPubKey], // Owner is the first admin
            members: members,     // Full member list
            createdAt: new Date()
        };

        const insertResult = await groupsCollection.insertOne(newGroup);

        // Return the full new group object, including its new _id
        const createdGroup = { ...newGroup, _id: insertResult.insertedId };

        log(`✅ Group Created: ${groupName} (ID: ${createdGroup._id}) by ${ownerPubKey.slice(0,10)}...`);
        res.status(201).json(createdGroup);

    } catch (err) {
        console.error("Group creation error:", err);
        res.status(500).json({ error: "Server error creating group." });
    }
});

// --- END: Group Chat API Endpoints (Phase 1) ---
/**
 * [AUTHENTICATED] Get metadata for a specific group.
 * Client must prove who they are and that they are a member.
 */
app.post("/group/meta", async (req, res) => {
    const { groupID, pubKey, signature } = req.body;
    if (!groupID || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    // Verify signature (user signed the groupID to prove request is fresh)
    const isAuthentic = await verifySignature(pubKey, signature, groupID);
    if (!isAuthentic) {
        return res.status(403).json({ error: "Invalid signature." });
    }

    try {
        const group = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        if (!group) {
            return res.status(404).json({ error: "Group not found." });
        }

        // Security check: Ensure the person asking is actually a member
        if (!group.members.includes(pubKey)) {
            return res.status(403).json({ error: "You are not a member of this group." });
        }

        // User is authenticated and is a member, send them the data.
        log(`[GroupMeta] User ${pubKey.slice(0,10)}... fetched meta for ${group.groupName}`);
        res.status(200).json(group);

    } catch (err) {
        console.error("Get /group/meta error:", err);
        res.status(500).json({ error: "Server error fetching group data." });
    }
});
/**
 * [AUTHENTICATED] Update a group's metadata (name, avatar).
 * Only an admin can do this.
 */
app.post("/group/update-meta", async (req, res) => {
    const { groupID, pubKey, signature, newName, newAvatar } = req.body;
    if (!groupID || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields." });
    }
    if (newName === undefined && newAvatar === undefined) {
        return res.status(400).json({ error: "Must provide newName or newAvatar." });
    }

    try {
        // 1. Find group
        const group = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        if (!group) return res.status(404).json({ error: "Group not found." });

        // 2. Verify user is an admin
        if (!group.admins.includes(pubKey)) {
            return res.status(403).json({ error: "You are not an admin of this group." });
        }

        // 3. Verify signature (admin signed the groupID + newName)
        // Note: We don't sign the avatar as it's too large.
        const dataToVerify = `${groupID}${newName || group.groupName}`;
        const isAuthentic = await verifySignature(pubKey, signature, dataToVerify);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        // 4. Build update
        const fieldsToUpdate = {};
        if (newName !== undefined) fieldsToUpdate.groupName = newName;
        if (newAvatar !== undefined) fieldsToUpdate.groupAvatar = newAvatar; // Can be null

        // 5. Perform update
        await groupsCollection.updateOne({ _id: group._id }, { $set: fieldsToUpdate });

        log(`[GroupMeta] Admin ${pubKey.slice(0,10)} updated group ${group.groupName}`);
        // 6. Notify all other members of the metadata change
        const membersToNotify = group.members.filter(m => m !== pubKey); // Don't notify the admin who made the change
        membersToNotify.forEach(memberPubKey => {
            const targetSocketId = userSockets[memberPubKey];
            if (targetSocketId) {
                io.to(targetSocketId).emit("group_meta_changed", { 
                    groupID: groupID, 
                    groupName: group.groupName // Send the (old) name for the toast
                });
            }
        });
        res.status(200).json({ success: true, ...fieldsToUpdate });

    } catch (err) {
        console.error("Group meta update error:", err);
        res.status(500).json({ error: "Server error updating group." });
    }
});

/**
 * [AUTHENTICATED] Add a member to a group.
 * Only an admin can do this.
 *//**
 * [AUTHENTICATED] Add one or more members to a group.
 * Only an admin can do this.
 */
app.post("/group/add-member", async (req, res) => {
    // --- UPDATED: Expect an array ---
    const { groupID, pubKey, signature, membersToAdd } = req.body;
    if (!groupID || !pubKey || !signature || !Array.isArray(membersToAdd) || membersToAdd.length === 0) {
        return res.status(400).json({ error: "Missing required fields (groupID, pubKey, signature, membersToAdd:[])." });
    }

    try {
        const group = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        if (!group) return res.status(404).json({ error: "Group not found." });

        // 1. Verify user is an admin
        if (!group.admins.includes(pubKey)) {
            return res.status(403).json({ error: "You are not an admin of this group." });
        }

        // 2. Verify signature (admin signed groupID + all new member PubKeys sorted)
        const membersString = [...membersToAdd].sort().join(',');
        const dataToVerify = `${groupID}${membersString}`;
        const isAuthentic = await verifySignature(pubKey, signature, dataToVerify);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        // 3. Add all new members to the 'members' array
        // $addToSet with $each adds all items from the array that aren't already present
        const updateResult = await groupsCollection.updateOne(
            { _id: group._id },
            { $addToSet: { members: { $each: membersToAdd } } }
        );

        log(`[Group] Admin ${pubKey.slice(0,10)} added ${membersToAdd.length} members to group ${group.groupName}`);

        // 4. Notify all other members of the roster change
        const updatedGroup = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        const membersToNotify = updatedGroup.members.filter(m => m !== pubKey); // Notify everyone else

        membersToNotify.forEach(memberPubKey => {
            const targetSocketId = userSockets[memberPubKey];
            if (targetSocketId) {
                io.to(targetSocketId).emit("group_roster_changed", { 
                    groupID: groupID, 
                    groupName: updatedGroup.groupName
                });
            }
        });

        res.status(200).json(updatedGroup); // Return the full new group doc

    } catch (err) {
        console.error("Group add member error:", err);
        res.status(500).json({ error: "Server error adding member." });
    }
});

/**
 * [AUTHENTICATED] Remove a member from a group.
 * Only an admin can do this.
 */
app.post("/group/remove-member", async (req, res) => {
    const { groupID, pubKey, signature, memberToRemovePubKey } = req.body;
    if (!groupID || !pubKey || !signature || !memberToRemovePubKey) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        const group = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        if (!group) return res.status(404).json({ error: "Group not found." });

        // 1. Verify user is an admin
        if (!group.admins.includes(pubKey)) {
            return res.status(403).json({ error: "You are not an admin of this group." });
        }

        // 2. Prevent admin from removing the last owner/admin
        if (group.owner === memberToRemovePubKey && group.admins.length === 1) {
            return res.status(403).json({ error: "Cannot remove the last admin/owner." });
        }

        // 3. Verify signature (admin signed groupID + memberToRemovePubKey)
        const dataToVerify = `${groupID}${memberToRemovePubKey}`;
        const isAuthentic = await verifySignature(pubKey, signature, dataToVerify);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        // 4. Remove the member
        const updateResult = await groupsCollection.updateOne(
            { _id: group._id },
            { 
                $pull: { 
                    members: memberToRemovePubKey,
                    admins: memberToRemovePubKey // Also remove from admin list if they were one
                } 
            }
        );

        log(`[Group] Admin ${pubKey.slice(0,10)} removed ${memberToRemovePubKey.slice(0,10)} from group ${group.groupName}`);

        // 5. Notify all remaining members
        const updatedGroup = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        const membersToNotify = updatedGroup.members.filter(m => m !== pubKey); 

        membersToNotify.forEach(memberPubKey => {
            const targetSocketId = userSockets[memberPubKey];
            if (targetSocketId) {
                io.to(targetSocketId).emit("group_roster_changed", { 
                    groupID: groupID,
                    groupName: updatedGroup.groupName
                });
            }
        });

        // 6. Also notify the person who was removed
        const removedSocketId = userSockets[memberToRemovePubKey];
        if (removedSocketId) {
             io.to(removedSocketId).emit("group_removed_from", { 
                groupID: groupID,
                groupName: updatedGroup.groupName
            });
        }

        res.status(200).json(updatedGroup); // Return the full new group doc

    } catch (err) {
        console.error("Group remove member error:", err);
        res.status(500).json({ error: "Server error removing member." });
    }
});

/**
 * [AUTHENTICATED] A member leaves a group.
 */
app.post("/group/leave", async (req, res) => {
    const { groupID, pubKey, signature } = req.body;
    if (!groupID || !pubKey || !signature) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        const group = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        if (!group) return res.status(404).json({ error: "Group not found." });

        // 1. Verify user is a member
        if (!group.members.includes(pubKey)) {
            return res.status(403).json({ error: "You are not a member of this group." });
        }

        // 2. Prevent owner from leaving if they are the last admin
        if (group.owner === pubKey && group.admins.length === 1) {
            return res.status(403).json({ error: "You are the last admin. You must delete the group instead." });
        }

        // 3. Verify signature (user signed the groupID)
        const isAuthentic = await verifySignature(pubKey, signature, groupID);
        if (!isAuthentic) {
            return res.status(403).json({ error: "Invalid signature." });
        }

        // 4. Remove the member
        await groupsCollection.updateOne(
            { _id: group._id },
            { 
                $pull: { 
                    members: pubKey,
                    admins: pubKey
                } 
            }
        );

        log(`[Group] Member ${pubKey.slice(0,10)} left group ${group.groupName}`);

        // 5. Notify all remaining members
        const updatedGroup = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
        updatedGroup.members.forEach(memberPubKey => { // Notify *all* remaining
            const targetSocketId = userSockets[memberPubKey];
            if (targetSocketId) {
                io.to(targetSocketId).emit("group_roster_changed", { 
                    groupID: groupID,
                    groupName: updatedGroup.groupName
                });
            }
        });

        res.status(200).json({ success: true });

    } catch (err) {
        console.error("Group leave error:", err);
        res.status(500).json({ error: "Server error leaving group." });
    }
});
// --- START: Simple Rate Limiting ---

// --- START: Simple Rate Limiting ---
const rateLimit = new Map();
const LIMIT = 20; // Max 20 requests
const TIME_FRAME = 60 * 1000; // per 60 seconds (1 minute)

function isRateLimited(socket) {
  const ip = socket.handshake.address;
  const now = Date.now();
  const record = rateLimit.get(ip);

  if (!record) {
    rateLimit.set(ip, { count: 1, startTime: now });
    return false;
  }

  // If time window has passed, reset
  if (now - record.startTime > TIME_FRAME) {
    rateLimit.set(ip, { count: 1, startTime: now });
    return false;
  }

  // If count exceeds limit, block the request
  if (record.count >= LIMIT) {
    return true;
  }

  // Otherwise, increment count and allow
  record.count++;
  return false;
}
// --- END: Simple Rate Limiting ---

// just to confirm server is alive
app.get("/", (req, res) => {
  res.send("✅ Signaling server is running");
});

// Map a user's permanent pubKey to their temporary socket.id
const userSockets = {};

// Map a pubKey to the list of sockets that are subscribed to it
// { "contact_PubKey": ["subscriber_socket_id_1", "subscriber_socket_id_2"] }
const presenceSubscriptions = {};

// Map a socket.id to the list of pubKeys it is subscribed to (for easy cleanup)
// { "subscriber_socket_id_1": ["contact_PubKey_A", "contact_PubKey_B"] }
const socketSubscriptions = {};

// Helper to normalize keys
function normKey(k){ return (typeof k === 'string') ? k.replace(/\s+/g,'') : k; }

io.on("connection", (socket) => {
  
  // Handle client registration
  socket.on("register", (pubKey) => {
    if (isRateLimited(socket)) {
      
      return;
    }
    if (!pubKey) return;
    const key = normKey(pubKey);
    userSockets[key] = socket.id;
    socket.data.pubKey = key; // Store key on socket for later cleanup
    console.log(`🔑 Registered: ${key.slice(0,12)}... -> ${socket.id}`);

    socket.emit('registered', { status: 'ok' });
    
  // --- Notify subscribers that this user is now online ---
    const subscribers = presenceSubscriptions[key];
    if (subscribers && subscribers.length) {
      console.log(`📢 Notifying ${subscribers.length} subscribers that ${key.slice(0,12)}... is online.`);
      subscribers.forEach(subscriberSocketId => {
        io.to(subscriberSocketId).emit("presence-update", { pubKey: key, status: "online" });
      });
    }
    
    // --- NEW: Check for offline relayed messages ---
    
// --- END NEW ---
 });
  
    // --- NEW: Check for offline relayed messages ---
    
        // --- END NEW ---
  
  
  // --- NEW: Handle client confirmation of message receipt ---
  socket.on("message-delivered", async (data) => {
      if (!data || !data.id) return;
      if (!socket.data.pubKey) return; // Client not registered

      try {
          const { ObjectId } = require("mongodb");
          const _id = new ObjectId(data.id);

          // We must check that the client confirming delivery
          // is the one the message was intended for.
          const deleteResult = await offlineMessagesCollection.deleteOne({
              _id: _id,
              recipientPubKey: socket.data.pubKey 
          });

          if (deleteResult.deletedCount === 1) {
              console.log(`✅ Message ${data.id} delivered to ${socket.data.pubKey.slice(0,10)}... and deleted from server.`);
          } else {
              console.warn(`⚠️ Message ${data.id} delivery confirmation failed (not found, or wrong recipient).`);
          }
      } catch (err) {
           console.error(`Error deleting delivered message ${data.id}:`, err);
      }
  });

    
  // --- NEW: Client "pull" request for offline messages ---
  socket.on("check-for-offline-messages", async () => {
      const key = socket.data.pubKey;
      if (!key) return; // Client not registered

      try {
          const messages = await offlineMessagesCollection.find({ recipientPubKey: key }).toArray();
          if (messages.length > 0) {
              console.log(`📬 Client ${key.slice(0,10)}... is pulling ${messages.length} relayed messages.`);
              messages.forEach(msg => {
                  socket.emit("offline-message", {
                      id: msg._id.toString(),
                      from: msg.senderPubKey,
                      payload: msg.encryptedPayload,
                      sentAt: msg.createdAt
                  });
              });
          } else {
               console.log(`📬 Client ${key.slice(0,10)}... pulled messages, 0 found.`);
          }
      } catch (err) {
          console.error(`Error fetching offline messages for ${key.slice(0,10)}:`, err);
      }
  });

    // --- NEW: Group Chat Listeners (Phase 1) ---

      socket.on("group_message", async ({ groupID, payload }) => {
          if (!groupID || !payload) return;
          const senderPubKey = socket.data.pubKey;
          if (!senderPubKey) return;

          try {
              const group = await groupsCollection.findOne({ _id: new ObjectId(groupID) });
              if (!group) {
                  return log(`[group_message] Group ${groupID} not found.`);
              }

              // Verify sender is a member
              if (!group.members.includes(senderPubKey)) {
                  return log(`[group_message] Sender ${senderPubKey.slice(0,10)} is not a member of group ${groupID}.`);
              }

              // Fan-out logic
              group.members.forEach(memberPubKey => {
                  if (memberPubKey === senderPubKey) return; // Don't send back to sender

                  const targetSocketId = userSockets[memberPubKey];
                  if (targetSocketId) {
                      // --- User is ONLINE ---
                      io.to(targetSocketId).emit("group_message_in", {
                          groupID,
                          payload,
                          from: senderPubKey
                      });
                  } else {
                      // --- User is OFFLINE ---
                      // Store in the new offline collection for groups
                      // We don't await this, let it run in the background
                      groupOfflineMessagesCollection.insertOne({
                          recipientPubKey: memberPubKey,
                          groupID,
                          from: senderPubKey,
                          payload,
                          createdAt: new Date(),
                          expireAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14-day TTL
                      }).catch(err => console.error(`Failed to store offline group message: ${err}`));
                  }
              });

          } catch (err) {
              console.error(`Error processing group_message: ${err}`);
          }
      });

      socket.on("check-for-group-offline-messages", async () => {
          const key = socket.data.pubKey;
          if (!key) return; // Client not registered

          try {
              const messages = await groupOfflineMessagesCollection.find({ recipientPubKey: key }).toArray();
              if (messages.length > 0) {
                  log(`📬 Client ${key.slice(0,10)}... is pulling ${messages.length} GROUP messages.`);
                  messages.forEach(msg => {
                      socket.emit("group_message_in", {
                          id: msg._id.toString(), // Add ID for deletion
                          groupID: msg.groupID,
                          from: msg.from,
                          payload: msg.payload,
                          sentAt: msg.createdAt
                      });
                  });
              } else {
                   log(`📬 Client ${key.slice(0,10)}... pulled GROUP messages, 0 found.`);
              }
          } catch (err) {
              console.error(`Error fetching offline GROUP messages for ${key.slice(0,10)}:`, err);
          }
      });

      socket.on("group-message-delivered", async (data) => {
          if (!data || !data.id) return;
          if (!socket.data.pubKey) return; // Client not registered

          try {
              const _id = new ObjectId(data.id);
              // Check that the client confirming is the recipient
              const deleteResult = await groupOfflineMessagesCollection.deleteOne({
                  _id: _id,
                  recipientPubKey: socket.data.pubKey 
              });

              if (deleteResult.deletedCount === 1) {
                  log(`✅ Group Message ${data.id} delivered to ${socket.data.pubKey.slice(0,10)}... and deleted.`);
              } else {
                  log(`⚠️ Group Message ${data.id} delivery confirmation failed (not found, or wrong recipient).`);
              }
          } catch (err) {
               console.error(`Error deleting delivered group message ${data.id}:`, err);
          }
      });

      // --- END: Group Chat Listeners (Phase 1) ---
  
  // Handle presence subscription
    socket.on("subscribe-to-presence", (contactPubKeys) => {
        console.log(`📡 Presence subscription from ${socket.id} for ${contactPubKeys.length} contacts.`);
  

        // --- 1. Clean up any previous subscriptions for this socket ---
      const oldSubscriptions = socketSubscriptions[socket.id];
      if (oldSubscriptions && oldSubscriptions.length) {
        oldSubscriptions.forEach(pubKey => {
          if (presenceSubscriptions[pubKey]) {
            presenceSubscriptions[pubKey] = presenceSubscriptions[pubKey].filter(id => id !== socket.id);
            if (presenceSubscriptions[pubKey].length === 0) {
              delete presenceSubscriptions[pubKey];
            }
          }
        });
    }

    // --- 2. Create the new subscriptions ---
    socketSubscriptions[socket.id] = contactPubKeys;
    contactPubKeys.forEach(pubKey => {
      const key = normKey(pubKey);
      if (!presenceSubscriptions[key]) {
        presenceSubscriptions[key] = [];
      }
      presenceSubscriptions[key].push(socket.id);
    });

    // --- 3. Reply with the initial online status of the subscribed contacts ---
    const initialOnlineContacts = contactPubKeys.filter(key => !!userSockets[normKey(key)]);
    socket.emit("presence-initial-status", initialOnlineContacts);
  });

  // Handle direct connection requests
  socket.on("request-connection", async ({ to, from }) => {
    if (isRateLimited(socket)) {
      
      return;
    }

    const toKey = normKey(to);
    const fromKey = normKey(from);
    const targetSocketId = userSockets[toKey];

    if (targetSocketId) {
      // --- This is the existing logic for ONLINE users ---
      io.to(targetSocketId).emit("incoming-request", { from: fromKey });
      console.log(`📨 Connection request (online): ${fromKey.slice(0, 12)}... → ${toKey.slice(0, 12)}...`);
    } else {
      // --- NEW LOGIC for OFFLINE users with Sleep Mode ---
     // (Inside the else block for offline users in socket.on("request-connection", ...))
      console.log(`- User ${toKey.slice(0, 12)}... is offline. No push notification configured/sent.`);
// All the 'storage.getItem', 'if (subscription)', and 'webpush' code is removed.
    }
  });

  // Handle connection acceptance
  socket.on("accept-connection", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
      io.to(targetId).emit("connection-accepted", { from: normKey(from) });
      console.log(`✅ Connection accepted: ${from.slice(0, 12)}... → ${to.slice(0, 12)}...`);
    } else {
      console.log(`⚠️ Could not deliver acceptance to ${to.slice(0,12)} (not registered/online)`);
    }
  });

  // server.js - New Code
// -- Video/Voice Call Signaling --
socket.on("call-request", ({ to, from, callType }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("incoming-call", { from: normKey(from), callType });
        console.log(`📞 Call request (${callType}): ${from.slice(0,12)}... → ${to.slice(0,12)}...`);
    }
});

socket.on("call-accepted", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("call-accepted", { from: normKey(from) });
        console.log(`✔️ Call accepted: ${from.slice(0,12)}... → ${to.slice(0,12)}...`);
    }
});

socket.on("call-rejected", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("call-rejected", { from: normKey(from) });
        console.log(`❌ Call rejected: ${from.slice(0,12)}... → ${to.slice(0,12)}...`);
    }
});

socket.on("call-ended", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("call-ended", { from: normKey(from) });
        console.log(`👋 Call ended: ${from.slice(0,12)}... & ${to.slice(0,12)}...`);
    }
});
// ---------------------------------


  // Room and signaling logic remains the same
  socket.on("join", (room) => {
    socket.join(room);
    console.log(`Client ${socket.id} joined ${room}`);
  });

  // Inside server.js
socket.on("auth", ({ room, payload }) => {
  // Log exactly what's received
  console.log(`[SERVER] Received auth for room ${room} from ${socket.id}. Kind: ${payload?.kind}`); // Added log
  try {
    // Log before attempting to emit
    console.log(`[SERVER] Relaying auth (Kind: ${payload?.kind}) to room ${room}...`); // Added log
    // Use io.to(room) to send to everyone in the room including potentially the sender if needed,
    // or socket.to(room) to send to everyone *except* the sender.
    // For auth handshake, io.to(room) or socket.to(room).emit should both work if both clients joined. Let's stick with socket.to for now.
    socket.to(room).emit("auth", { room, payload });
    console.log(`[SERVER] Successfully emitted auth to room ${room}.`); // Added log
  } catch (error) {
    console.error(`[SERVER] Error emitting auth to room ${room}:`, error); // Added error log
  }
});

// ALSO add logging for the 'signal' handler for WebRTC messages:
socket.on("signal", ({ room, payload }) => {
  console.log(`[SERVER] Received signal for room ${room} from ${socket.id}.`); // Added log
  console.log(`[SERVER] Relaying signal to room ${room}...`); // Added log
  socket.to(room).emit("signal", { room, payload }); // Assuming payload includes 'from' etc needed by client
  console.log(`[SERVER] Successfully emitted signal to room ${room}.`); // Added log
});

  socket.on("disconnect", () => {
    
    const pubKey = socket.data.pubKey;

    if (pubKey) {
      // --- 1. Notify subscribers that this user is now offline ---
      const subscribers = presenceSubscriptions[pubKey];
      if (subscribers && subscribers.length) {
        console.log(`📢 Notifying ${subscribers.length} subscribers that ${pubKey.slice(0,12)}... is offline.`);
        subscribers.forEach(subscriberSocketId => {
          io.to(subscriberSocketId).emit("presence-update", { pubKey: pubKey, status: "offline" });
        });
      }

      // --- 2. Clean up all subscriptions this socket made ---
      const subscriptionsMadeByThisSocket = socketSubscriptions[socket.id];
      if (subscriptionsMadeByThisSocket && subscriptionsMadeByThisSocket.length) {
        subscriptionsMadeByThisSocket.forEach(subscribedToKey => {
          if (presenceSubscriptions[subscribedToKey]) {
            presenceSubscriptions[subscribedToKey] = presenceSubscriptions[subscribedToKey].filter(id => id !== socket.id);
            if (presenceSubscriptions[subscribedToKey].length === 0) {
              delete presenceSubscriptions[subscribedToKey];
            }
          }
        });
      }
      delete socketSubscriptions[socket.id];

      // --- 3. Finally, remove user from the main online list ---
      delete userSockets[pubKey];
      console.log(`🗑️ Unregistered and cleaned up subscriptions for: ${pubKey.slice(0, 12)}...`);
    }
  });
});

const PORT = process.env.PORT || 3000;

// Connect to MongoDB *before* starting the HTTP server
connectToMongo().then(() => {
    server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}).catch(err => {
    console.error("🚨 MongoDB connection failed on startup. Server not started.", err);
});

// --- Add graceful shutdown for MongoDB ---
process.on('SIGINT', async () => {
    console.log("🔌 Shutting down server...");
    await mongoClient.close();
    console.log("🔒 MongoDB connection closed.");
    process.exit(0);
});
