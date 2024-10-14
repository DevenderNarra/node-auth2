const express = require("express");
const { open } = require("sqlite");
const path = require("path");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken"); // JWT for authentication
const app = express();
app.use(express.json());

const dbPath = path.join(__dirname, "covid19IndiaPortal.db");
let db = null;

const secretKey = "your_secret_key"; // Use an environment variable for better security

const initializeServerAndDb = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server runs at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`Error: ${e.message}`);
    process.exit(1);
  }
};
initializeServerAndDb();

// Authentication middleware to validate JWT token
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return response.status(401).send("Invalid JWT Token");
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return response.status(401).send("Invalid JWT Token");
    }
    request.user = user;
    next();
  });
};

// Login API to authenticate user and return a JWT token
app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `SELECT * FROM user WHERE username = ?;`;
  const dbUser = await db.get(selectUserQuery, [username]);

  if (dbUser === undefined) {
    response.status(400).send("Invalid user");
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched) {
      const payload = { username: username };
      const jwtToken = jwt.sign(payload, secretKey);
      response.send({ jwtToken });
    } else {
      response.status(400).send("Invalid password");
    }
  }
});

// Protected route to get all states, requires token
app.get("/states/", authenticateToken, async (request, response) => {
  const getStateQuery = `SELECT state_id AS stateId, state_name AS stateName, population FROM state;`;
  const statesArray = await db.all(getStateQuery);
  response.send(statesArray);
});

// Protected route to get a state by ID
app.get("/states/:stateId/", authenticateToken, async (request, response) => {
  const { stateId } = request.params;
  const getStateQuery = `SELECT state_id AS stateId, state_name AS stateName, population FROM state WHERE state_id = ?;`;
  const state = await db.get(getStateQuery, [stateId]);
  response.send(state);
});

// Protected route to create a new district
app.post("/districts/", authenticateToken, async (request, response) => {
  const { districtName, stateId, cases, cured, active, deaths } = request.body;
  const createDistrictQuery = `
    INSERT INTO district (district_name, state_id, cases, cured, active, deaths)
    VALUES (?, ?, ?, ?, ?, ?);
  `;
  await db.run(createDistrictQuery, [
    districtName,
    stateId,
    cases,
    cured,
    active,
    deaths,
  ]);
  response.send("District Successfully Added");
});

// Protected route to get a district by ID
app.get(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const getDistrictQuery = `
    SELECT district_id AS districtId, district_name AS districtName, state_id AS stateId, 
           cases, cured, active, deaths 
    FROM district WHERE district_id = ?;
  `;
    const district = await db.get(getDistrictQuery, [districtId]);
    response.send(district);
  }
);

// Protected route to delete a district by ID
app.delete(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const deleteDistrictQuery = `DELETE FROM district WHERE district_id = ?;`;
    await db.run(deleteDistrictQuery, [districtId]);
    response.send("District Removed");
  }
);

// Protected route to update district details by ID
app.put(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const {
      districtName,
      stateId,
      cases,
      cured,
      active,
      deaths,
    } = request.body;
    const updateDistrictQuery = `
    UPDATE district 
    SET district_name = ?, state_id = ?, cases = ?, cured = ?, active = ?, deaths = ?
    WHERE district_id = ?;
  `;
    await db.run(updateDistrictQuery, [
      districtName,
      stateId,
      cases,
      cured,
      active,
      deaths,
      districtId,
    ]);
    response.send("District Details Updated");
  }
);

// Protected route to get statistics for a state
app.get(
  "/states/:stateId/stats/",
  authenticateToken,
  async (request, response) => {
    const { stateId } = request.params;
    const getStateStatsQuery = `
    SELECT SUM(cases) AS totalCases, SUM(cured) AS totalCured, SUM(active) AS totalActive, 
           SUM(deaths) AS totalDeaths 
    FROM district WHERE state_id = ?;
  `;
    const stats = await db.get(getStateStatsQuery, [stateId]);
    response.send(stats);
  }
);

module.exports = app;
