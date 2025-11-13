const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const crypto = require('crypto');
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb"); // Import MongoDB client & ObjectId

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
  allowedHeaders: "Content-Type" // Allow the JSON content type header
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
            createdAt: new Date()
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
        const channel = await channelsCollection.findOne({ _id: new ObjectId(channelId) });
        if (!channel) {
            return res.status(404).json({ error: "Channel not found." });
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

/**
 * [ANONYMOUS] Fetch new messages for followed channels.
 * This is the main "pull" endpoint for followers.
 */
app.post("/channels/fetch", async (req, res) => {
    const { channels } = req.body; // e.g., [{ id: "...", since: "..." }]
    if (!Array.isArray(channels) || channels.length === 0) {
        return res.json([]);
    }

    try {
        // Build a query for each channel
        const queries = channels.map(c => ({
            channelId: new ObjectId(c.id),
            createdAt: { $gt: new Date(c.since) }
        }));

        // Find all messages matching any of the queries
        const allNewMessages = await channelUpdatesCollection
            .find({ $or: queries })
            .sort({ createdAt: 1 }) // Send oldest-to-newest
            .toArray();

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
  console.log("Client connected:", socket.id);

  // Handle client registration
  socket.on("register", (pubKey) => {
    if (isRateLimited(socket)) {
      console.log(`⚠️ Rate limit exceeded for registration by ${socket.handshake.address}`);
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
      console.log(`⚠️ Rate limit exceeded for request-connection by ${socket.handshake.address}`);
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
    console.log("Client disconnected:", socket.id);
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
