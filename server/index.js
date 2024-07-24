import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { GoogleGenerativeAI } from "@google/generative-ai";
import pg from "pg";

dotenv.config();
const app = express();
const port = process.env.PORT;
const saltRounds = 10;

const db = new pg.Client({
    user: process.env.USER,
    host: process.env.HOST,
    database: process.env.DATABASE,
    password: process.env.PASSWORD,
    port: process.env.DB_PORT
})

db.connect();

app.use(cors({ origin: process.env.PUBLIC_URL, methods: ["GET", "POST", "PUT", "PATCH", "DELETE"], credentials: true }));
app.use(express.json());

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Use secure: true in production
  }));

app.use(passport.initialize());
app.use(passport.session());

// Accessing API token
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

// Initialize chat history
let chatHistory = [];

app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
  
    try {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const newUserQuery = `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *`;
      const values = [name, email, hashedPassword];
  
      const newUser = await db.query(newUserQuery, values);
  
      console.log("User registered:", newUser.rows[0]);
  
      res.status(201).json({ message: "User registered successfully", user: newUser.rows[0] });
    } catch (error) {
      if (error.code === '23505' && error.constraint === 'users_email_key') {
        // Unique constraint violation on the 'email' field
        console.log("User already exists");
        return res.status(400).json({ error: "Email address is already registered" });
      }
  
      console.error("Error registering user:", error);
      res.status(500).json({ error: "An error occurred while registering the user" });
    }
  });
  
  // Login endpoint
  app.post("/login", async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const userQuery = `SELECT * FROM users WHERE email = $1`;
      const values = [email];
  
      const userResult = await db.query(userQuery, values);
      const user = userResult.rows[0];
  
      if (!user) {
        return res.status(400).json({ error: "User not found" });
      }
  
      const passwordMatch = await bcrypt.compare(password, user.password);
  
      if (!passwordMatch) {
        return res.status(400).json({ error: "Incorrect password" });
      }
  
      // If user and password are correct, you can proceed with authentication
      // For example, you could generate a JWT token and send it to the frontend
      // Here, we'll simply send a success message for demonstration purposes
      res.status(200).json({ message: "Login successful", user });
    } catch (error) {
      console.error("Error logging in:", error);
      res.status(500).json({ error: "An error occurred while logging in" });
    }
  });

app.post("/userSearch", async (req, res) => {
    let { selectedService, location } = req.body;
    selectedService = selectedService.toLowerCase();
    console.log(selectedService);
    console.log(location);

    try {
        // Query to retrieve service providers based on selected service and location
        const query = `
            SELECT DISTINCT sp.provider_id, sp.provider_name, sp.email, sp.phone, sp.website, sp.logo_url, sp.description, sp.rating, sp.certifications, sp.services_offered, sp.locations_served
            FROM ServiceProviders sp
            JOIN ServiceProviderServices sps ON sp.provider_id = sps.provider_id
            JOIN ServiceProviderLocations spl ON sp.provider_id = spl.provider_id
            JOIN Services s ON sps.service_id = s.service_id
            JOIN Locations l ON spl.location_id = l.location_id
            WHERE LOWER(s.service_name) = $1
            AND LOWER(l.location_name) = $2;
        `;
        const result = await db.query(query, [selectedService, location.toLowerCase()]);

        if (result.rows.length > 0) {
            console.log("Service providers found:", result.rows);
            res.status(200).json({ message: "Service providers found", serviceProviders: result.rows });
        } else {
            console.log("No service providers found for the selected service and location.");
            res.status(404).json({ message: "No service providers found for the selected service and location." });
        }
    } catch (error) {
        console.error("Error searching for service providers:", error);
        res.status(500).json({ error: "An error occurred while searching for service providers" });
    }
});

let serviceData = [];
let serviceDataUpdateCallback = null;

app.post('/serviceList', (req, res) => {
  const receivedService = req.body.receivedService;
  console.log("Received service:", receivedService);
  // Update the global serviceData with the received service
  serviceData = receivedService;
  console.log("Updated serviceData:", serviceData);
  // If a callback is set, invoke it to notify that serviceData has been updated
  if (serviceDataUpdateCallback) {
    serviceDataUpdateCallback();
    serviceDataUpdateCallback = null; // Reset the callback
  }
  res.json({ message: "Service data updated successfully" });
});

app.get('/serviceLists', (req, res) => {
  // Send the stored service data as a response only after serviceData is updated
  const sendResponse = () => {
    console.log("Sending serviceData:", serviceData);
    res.json({ service: serviceData });
  };

  // Check if serviceData is empty, if so, wait for it to be updated
  if (serviceData.length === 0) {
    console.log("Waiting for serviceData to be updated...");
    // Set a callback to notify when serviceData is updated
    serviceDataUpdateCallback = sendResponse;
  } else {
    sendResponse(); // Send the response immediately if serviceData is already updated
  }
});







let selectedService = null;
let selectedServiceUpdateCallback = null;

app.post('/selectedService', (req, res) => {
    const receivedSelectedService = req.body.service;
    console.log("Received selected service:", receivedSelectedService);
    // Update the global selectedService with the received service
    selectedService = receivedSelectedService;
    console.log("Updated selectedService:", selectedService);
    // If a callback is set, invoke it to notify that selectedService has been updated
    if (selectedServiceUpdateCallback) {
        selectedServiceUpdateCallback();
        selectedServiceUpdateCallback = null; // Reset the callback
    }
    res.json({ message: "Selected service data updated successfully" });
});

app.get('/getSelectedService', async (req, res) => {
    // Send the stored selected service data along with additional details
    const sendResponse = async () => {
        try {
            console.log("Fetching details for selected service:", selectedService);
            // Fetch previous works for the selected service from the database
            const previousWorksQuery = `
                SELECT * FROM PreviousWorks WHERE provider_id = $1;
            `;
            const previousWorksResult = await db.query(previousWorksQuery, [selectedService.provider_id]);

            // Fetch customer reviews for the selected service from the database
            const customerReviewsQuery = `
                SELECT * FROM CustomerReviews WHERE provider_id = $1;
            `;
            const customerReviewsResult = await db.query(customerReviewsQuery, [selectedService.provider_id]);

            // Fetch customer details for the customer reviews from the database
            const customerDetailsQuery = `
                SELECT * FROM CustomerDetails WHERE review_id IN (
                    SELECT review_id FROM CustomerReviews WHERE provider_id = $1
                );
            `;
            const customerDetailsResult = await db.query(customerDetailsQuery, [selectedService.provider_id]);

            const responseData = {
                service: selectedService,
                previousWorks: previousWorksResult.rows,
                customerReviews: customerReviewsResult.rows,
                customerDetails: customerDetailsResult.rows
            };

            console.log("Sending selected service details:", responseData);
            res.json(responseData);
        } catch (error) {
            console.error("Error fetching details for selected service:", error);
            res.status(500).json({ error: "An error occurred while fetching details for selected service" });
        }
    };

    // Check if selectedService is null, if so, wait for it to be updated
    if (!selectedService) {
        console.log("Waiting for selectedService to be updated...");
        // Set a callback to notify when selectedService is updated
        selectedServiceUpdateCallback = sendResponse;
    } else {
        sendResponse(); // Send the response immediately if selectedService is already updated
    }
});



/*app.post('/service-provider/login', async(req, res)=>{
    const { code, username, password } = req.body;
try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Insert the provider_id, email, and hashed password into the database
    const query = `
        INSERT INTO ServiceProviderAuth (provider_id, username, password_hash)
        VALUES ($1, $2, $3)
    `;
    await db.query(query, [code, username, hashedPassword]);

    res.status(200).json({ message: "Login successful" });
} catch (error) {
    console.error("Error inserting data:", error);
    res.status(500).json({ error: "An error occurred while processing your request" });
}
})
.......this is to sign up service providers*/

app.post('/service-provider/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if the username exists in ServiceProviderAuth table
        const authQuery = 'SELECT * FROM ServiceProviderAuth WHERE username = $1';
        const authResult = await db.query(authQuery, [username]);

        if (authResult.rows.length === 0) {
            // Username not found
            console.log('Username not found');
            return res.status(404).json({ message: 'Username not found' });
        }

        // Check if the provided password matches the hashed password in the database
        const hashedPassword = authResult.rows[0].password_hash;
        const passwordMatch = await bcrypt.compare(password, hashedPassword);

        if (!passwordMatch) {
            // Incorrect password
            console.log('Incorrect password');
            return res.status(401).json({ message: 'Incorrect password' });
        }

        // If username and password are correct, fetch details of the service provider
        const providerId = authResult.rows[0].provider_id;
        console.log('Fetching service provider details...');
        const serviceProviderQuery = 'SELECT * FROM ServiceProviders WHERE provider_id = $1';
        const serviceProviderResult = await db.query(serviceProviderQuery, [providerId]);
        console.log('Service provider details:', serviceProviderResult.rows[0]);

        // Fetch previous works of the service provider from the PreviousWorks table
        console.log('Fetching previous works...');
        const previousWorksQuery = 'SELECT * FROM PreviousWorks WHERE provider_id = $1';
        const previousWorksResult = await db.query(previousWorksQuery, [providerId]);
        console.log('Previous works:', previousWorksResult.rows);

        // Fetch customer reviews of the service provider
        console.log('Fetching customer reviews...');
        const customerReviewsQuery = 'SELECT * FROM CustomerReviews WHERE provider_id = $1';
        const customerReviewsResult = await db.query(customerReviewsQuery, [providerId]);
        console.log('Customer reviews:', customerReviewsResult.rows);

        // Fetch customer details for the customer reviews
        console.log('Fetching customer details...');
        const customerDetailsQuery = `
            SELECT cd.* FROM CustomerDetails cd
            INNER JOIN CustomerReviews cr ON cd.review_id = cr.review_id
            WHERE cr.provider_id = $1
        `;
        const customerDetailsResult = await db.query(customerDetailsQuery, [providerId]);
        console.log('Customer details:', customerDetailsResult.rows);

        // Combine the service provider details, previous works, customer reviews, and customer details
        const serviceProviderDetails = {
            provider: serviceProviderResult.rows[0],
            previousWorks: previousWorksResult.rows,
            customerReviews: customerReviewsResult.rows,
            customerDetails: customerDetailsResult.rows
        };

        res.status(200).json(serviceProviderDetails);
    } catch (error) {
        console.error('Error logging in service provider:', error);
        res.status(500).json({ error: 'An error occurred while logging in service provider' });
    }
});


app.patch("/updatedServiceDetails", async (req, res) => {
    try {
        const { serviceProviderId, description, email, phone, website } = req.body;

        // Generate the dynamic SET clause based on the received data
        let setClause = "";
        const updateValues = [];
        let index = 1; // Parameter index for the updateValues array

        if (description) {
            setClause += `description = $${index}, `;
            updateValues.push(description);
            index++;
        }
        if (email) {
            setClause += `email = $${index}, `;
            updateValues.push(email);
            index++;
        }
        if (phone) {
            setClause += `phone = $${index}, `;
            updateValues.push(phone);
            index++;
        }
        if (website) {
            setClause += `website = $${index}, `;
            updateValues.push(website);
            index++;
        }

        // Remove the trailing comma and space from the SET clause
        setClause = setClause.slice(0, -2);

        // Construct the UPDATE query
        const updateQuery = `
            UPDATE ServiceProviders
            SET ${setClause}
            WHERE provider_id = $${index};`;

        // Add the serviceProviderId to the end of the updateValues array
        updateValues.push(serviceProviderId);

        // Execute the UPDATE query
        await db.query(updateQuery, updateValues);

        res.status(200).json({ message: "Service provider details updated successfully" });
    } catch (error) {
        console.error("Error updating service provider details:", error);
        res.status(500).json({ error: "An error occurred while updating service provider details" });
    }
});























app.post("/new", async (req, res) => {
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });
    const userInput = req.body.userInput;
    console.log(userInput);

    // Generating response from the AI model
    try {
        const result = await model.generateContent(userInput);
        const response = await result.response;
        const text = response.text();

        // Add user input and AI response to chat history
        chatHistory.push({ role: "user", text: userInput });
        chatHistory.push({ role: "assistant", text: text });

        console.log(chatHistory);

        // Send the updated chat history to the client
        res.json({ chatHistory });

        // Clear the chat history to avoid accumulation
        chatHistory = [];
    } catch (error) {
        console.error("Error generating response:", error);
        chatHistory.push({ role: "assistant", text: "Oops! Something went wrong." });
        res.status(500).json({ error: "An error occurred while generating response" });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
