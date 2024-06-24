const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const app = express();
const port = process.env.PORT || 5000;
const axios = require("axios");
const stripe = require("stripe")(process.env.Stripe_Secret_Key);

//middleware
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174", "https://66797bb9235f9bb1d8a5c340--splendorous-trifle-6f2238.netlify.app" ],
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_Users}:${process.env.DB_Pass}@cluster0.esdmpuv.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
const cookieOptions = {
  httpOnly: true,
  sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
  secure: process.env.NODE_ENV === "production" ? true : false,
};
async function run() {
  try {
    const database = client.db("pet-house");
    const RegisterUser = database.collection("RegisterUser");
    const PetsCollection = database.collection("PetsCollection");
    const DonationCampaigns = database.collection("DonationCampaigns");
    const DonateMoneyCollection = database.collection("DonateMoneyCollection");
    const AdoptRequestCollection = database.collection(
      "AdoptRequestCollection"
    );
    const RefundCollection = database.collection("RefundCollection");

    //=====================================Middleware==============================

    //custom middleware
    //verify the token
    const verifyToken = async (req, res, next) => {
      const token = req.cookies?.token;
      if (!token) {
        return res.status(401).send({ message: "Not Authorize" });
      }
      jwt.verify(token, process.env.Access_Token_Secret, (err, decoded) => {
        //error
        if (err) {
          return res.status(401).send({ message: "Not Authorize" });
        }

        //if token is valid the decoded means the email which send in /jwt api

        //if the token is valid then the token data set on user_email(we can create any name)
        req.user_email = decoded;
        next();
      });
    };

    //verify the Admin after the verify token
    //this mainly use in Admin all called API
    const verifyAdmin = async (req, res, next) => {
      const User_Email = req.user_email.email; //always verifyAdmin midilware after verifyTokten
      const query = { email: User_Email };
      const user = await RegisterUser.findOne(query);
      const IsAdmin = user?.role === "Admin" ? true : false;
      if (!IsAdmin) {
        return res.status(403).send({ message: "forbidden" });
      }
      next();
    };

    //-------------------================= jwt token Api ================------------------------------
    //access token always create when a user log in in our system
    app.post("/jwt", async (req, res) => {
      const user = req.body;

      const token = jwt.sign(user, process.env.Access_Token_Secret, {
        expiresIn: "1h",
      });
      // {
      //   httpOnly: true,
      //   secure: false, // when in production set true
      // }
      res.cookie("token", token, cookieOptions).send({ success: true });
    });
    //clear the access token when user log out
    app.post("/logout", async (req, res) => {
      const user = req.body;
      res
        .clearCookie("token", { ...cookieOptions, maxAge: 0 })
        .send({ Logout_Success: true });
    });
    //=======================================Admin Api========================================
    //--------------------------------------Check the Admin ----------------------------
    app.get(`/Check_Admin/:email`, verifyToken, async (req, res) => {
      const email = req.params.email;
      //check the email and decoder email(from verifyToken) are same or not
      if (email !== req.user_email.email) {
        return res.status(403).send({ message: "UnAuthorize Access" });
      }
      const query = { email: email };
      const user = await RegisterUser.findOne(query);
      let IsAdmin = false;

      if (user) {
        IsAdmin = user?.role === "Admin" ? true : false;
      }

      res.send({ IsAdmin });
    });
    //-----------------------------------All users
    app.get("/AllUsers/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.limit);
      const query = { email: { $ne: email } };
      const result = await RegisterUser.find(query)
        .skip(page * size)
        .limit(size)
        .toArray();
      res.send(result);
    });
    //------------------------------------Users count
    app.get("/Users/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const query = { email: { $ne: email } };
      const result = await RegisterUser.countDocuments(query);
      res.send({ count: result });
    });
    //-----------------------------------Donation_Count
    app.get("/Donation_Count", verifyToken, verifyAdmin, async (req, res) => {
      const result = await DonationCampaigns.countDocuments();
      res.send({ count: result });
    });

    //-----------------------------------Pet_counts
    app.get("/Pet_counts", verifyToken, verifyAdmin, async (req, res) => {
      const result = await PetsCollection.countDocuments();
      res.send({ count: result });
    });

    //------------------------------------Make Admin
    app.patch(
      "/MakeAdmin/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;
        const filter = { email: email };
        const updateDoc = {
          $set: { role: "Admin" },
        };
        const result = await RegisterUser.updateOne(filter, updateDoc);
        res.send(result);
      }
    );
    //------------------------------------Make Ban
    app.patch("/MakeBan/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const Status = req.query.status == "Ban" ? "Active" : "Ban";

      const filter = { email: email };

      const updateDoc = {
        $set: { Status: Status },
      };

      const result = await RegisterUser.updateOne(filter, updateDoc);
      res.send(result);
    });
    //--------------------------------------Check Ban
    app.get("/userStatus/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await RegisterUser.findOne(query);
      res.send(result);
    });
    //------------------------------------All pets
    app.get("/AllPets/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.limit);
      const result = await PetsCollection.find()
        .skip(page * size)
        .limit(size)
        .toArray();
      res.send(result);
    });
    //-------------------------------------AllPetCount
    app.get("/AllPetCount", verifyToken, verifyAdmin, async (req, res) => {
      const result = await PetsCollection.countDocuments();
      res.send({ count: result });
    });
    //--------------------------------------adoptAllPets
    app.patch(
      "/adoptAllPets/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const Adopted = req.query.Adopted === "true" ? false : true;

        const query = {
          _id: new ObjectId(id),
        };
        const updatedDoc = {
          $set: {
            Adopted: Adopted,
          },
        };
        const result = await PetsCollection.updateOne(query, updatedDoc);
        res.send(result);
      }
    );
    //--------------------------------------AllDonation
    app.get(
      "/AllDonation/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const page = parseInt(req.query.page);
          const size = parseInt(req.query.limit);

          if (isNaN(page) || isNaN(size)) {
            return res
              .status(400)
              .json({ message: "Invalid page or limit parameter" });
          }
          // Pagination
          const result = await DonationCampaigns.find()
            .skip(page * size)
            .limit(size)
            .toArray();

          let UpdateResult = [];

          for (const item of result) {
            const rules = {
              DonationItem_ID: item._id.toHexString(),
            };
            const ItemBasedDonation = await DonateMoneyCollection.find(rules, {
              projection: { amount: 1 },
            }).toArray();

            let TotalAmount = ItemBasedDonation.reduce(
              (total, donation) => total + donation.amount,
              0
            );
            let Progress = Math.round(
              (TotalAmount / (item.MaxDonation * 100)) * 100
            );

            UpdateResult.push({ ...item, Progress });
          }

          res.send(UpdateResult);
        } catch (error) {
          res.status(500).json({ message: "Internal server error", error });
        }
      }
    );
    //------------------------------------AllDonationCount
    app.get("/AllDonationCount", verifyToken, verifyAdmin, async (req, res) => {
      const result = await DonationCampaigns.countDocuments();
      res.send({ count: result });
    });
    //--------------------------------User Dashboard area Chart Data create
    app.get(
      "/AllDonationHistory_Admin",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        //find All Donation of user
        const query = {};
        const option = {
          projection: {
            _id: 1,
          },
        };
        const DonateID = await DonationCampaigns.find(query, option).toArray();

        let Donate = [];
        let refund = [];
        //find donate money based on DonateID
        for (const item of DonateID) {
          const query3 = { DonationItem_ID: item._id.toHexString() };
          const option3 = {
            projection: {
              _id: 0,
              amount: 1,
              user_name: 1,
              date: 1,
            },
          };
          const DonateData = await DonateMoneyCollection.find(
            query3,
            option3
          ).toArray();

          const RefundData = await RefundCollection.find(
            query3,
            option3
          ).toArray();

          for (const item of DonateData) {
            Donate.push(item);
          }
          for (const item of RefundData) {
            refund.push(item);
          }
        }
        //now combine all Donate data based on same date
        const combineDonate = [];
        const DonateDetails = [];
        let Total = 0;
        for (let item of Donate) {
          const date = item.date.split("T")[0];
          const data = Donate.some((item) => {
            if (item.date.split("T")[0] === date) {
              Total += item.amount;
            }
          });
          Total = Total / 100;
          combineDonate.push({ date: date, Donate: Total });
          DonateDetails.push({
            date: date,
            amount: item.amount / 100,
            user_name: item.user_name,
            refund: false,
          });
          Total = 0;
        }

        //now combine all Refund data based on same date
        for (let item of refund) {
          const date = item.date.split("T")[0];
          const data = refund.some((item) => {
            if (item.date.split("T")[0] === date) {
              Total += item.amount;
            }
          });
          Total = Total / 100;
          combineDonate.push({ date: date, Refund: Total });
          DonateDetails.push({
            date: date,
            amount: item.amount / 100,
            user_name: item.user_name,
            refund: true,
          });
          Total = 0;
        }
        //Remove Duplicate data
        const uniqueData = Array.from(
          new Set(combineDonate.map(JSON.stringify))
        ).map(JSON.parse);

        const combinedData = {};

        // Combine data based on date
        uniqueData.forEach((entry) => {
          const { date, Donate = 0, Refund = 0 } = entry;
          if (!combinedData[date]) {
            combinedData[date] = { date, Donate: 0, Refund: 0 };
          }
          combinedData[date].Donate += Donate;
          combinedData[date].Refund += Refund;
        });

        // Convert the combined data object back to an array
        const result = Object.values(combinedData);
        // Sort the result array by date
        result.sort((a, b) => new Date(a.date) - new Date(b.date));
        DonateDetails.sort((a, b) => new Date(b.date) - new Date(a.date));

        // Send the result as the response
        res.send({ result, DonateDetails });
      }
    );

    //------------------------------------ Amin Dashboard Pie Chart Data create
    app.get("/userDetails", verifyToken, verifyAdmin, async (req, res) => {
      const result = [];
      //find the active users
      const query = {
        Status: "Active",
      };
      const activeUsers = await RegisterUser.countDocuments(query);
      result.push({
        name: "Active Members",
        value: activeUsers,
      });

      //find the inactive users
      const option = {
        projection: {
          _id: 0,
          LastLogin_Date: 1,
        },
      };
      const inactiveUsers = await RegisterUser.find().toArray();
      let inactiveUsersCount = 0;
      for (let date of inactiveUsers) {
        const lastLoginDate = new Date(parseInt(date.LastLogin_Date));
        // Get the current date
        const currentDate = new Date();
        // Calculate the date one week ago from the current date
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(currentDate.getDate() - 7);
        // Check if the last login date is before one week ago
        if (lastLoginDate < oneWeekAgo) {
          inactiveUsersCount++;
        }
      }
      result.push({
        name: "Inactive Members",
        value: inactiveUsersCount,
      });
      //Find the total number of users
      const totalUsers = await RegisterUser.countDocuments();
      result.push({
        name: "All Members",
        value: totalUsers,
      });
      //Total Users
      const Users = await RegisterUser.countDocuments({ role: "user" });
      result.push({
        name: "User",
        value: Users,
      });
      //Total Admin from the users
      const totalAdmin = await RegisterUser.countDocuments({ role: "Admin" });
      result.push({
        name: "Admin",
        value: totalAdmin,
      });

      res.send({ result });
    });
    //======================================  All Api ============================

    //---------------------pagination all pets
    app.get("/petCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Author_email: email };
      const count = await PetsCollection.countDocuments(query);
      res.send({ count });
    });
    //----------------------My added pets data get Api
    app.get("/myPets/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.limit);

      const query = { Author_email: email };
      const result = await PetsCollection.find(query)
        .skip(page * size)
        .limit(size)
        .toArray();
      res.send(result);
    });
    //---------------------User register data post Api
    app.post("/registerUsers", async (req, res) => {
      const user = req.body;
      const query = { email: user.email };
      const existingUser = await RegisterUser.findOne(query);
      if (!existingUser) {
        const result = await RegisterUser.insertOne(user);
        return res.send(result);
      }
      res.send({ message: "user already exist" });
    });

    //----------------------Add pets data post Api
    app.post("/AddPets", verifyToken, async (req, res) => {
      const AddPets = req.body;
      const result = await PetsCollection.insertOne(AddPets);
      res.send(result);
    });

    //------------------------Adopted patch Api
    app.patch("/adopt/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          Adopted: true,
        },
      };
      const result = await PetsCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });
    //------------------------post Adopted request
    app.post("/PetAdopt", verifyToken, async (req, res) => {
      const PetAdopt = req.body;
      const result = await AdoptRequestCollection.insertOne(PetAdopt);
      res.send(result);
    });
    //------------------------user dashboard AdoptionRequest
    app.get("/AdoptionRequest/:email", verifyToken, async (req, res) => {
      const User_email = req.params.email;
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.limit);
      const query = { Author_email: User_email, Status: "Pending" };

      const result = await AdoptRequestCollection.find(query)
        .skip(page * size)
        .limit(size)
        .toArray();

      res.send(result);
    });
    //-----------------------------AdoptionRequestCount counts
    app.get("/AdoptionRequestCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Author_email: email, Status: "Pending" };
      const count = await AdoptRequestCollection.countDocuments(query);
      res.send({ count });
    });
    //-----------------------------RequestStatus_Count counts
    app.get("/RequestStatus_Count/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Adopt_email: email };
      const count = await AdoptRequestCollection.countDocuments(query);
      res.send({ count });
    });
    //-------------------------------AcceptRequestCount
    app.get("/AcceptRequestCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Author_email: email, Status: "Accepted" };
      const count = await AdoptRequestCollection.countDocuments(query);
      res.send({ count });
    });
    //-----------------------------AdoptedRequest_update
    app.patch("/AdoptedRequest_update/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const petID = req.query.petID;
      //auto rejected others
      const rejectQuery = {
        PetId: petID,
      };
      const rejectOption = { upsert: true };
      const rejectUpdatedDoc = {
        $set: {
          Status: "Rejected",
        },
      };
      const rejectResult = await AdoptRequestCollection.updateMany(
        rejectQuery,
        rejectUpdatedDoc,
        rejectOption
      );
      // after rejected accepted the select one and update the pets collection
      if (rejectResult.modifiedCount > 0) {
        //accepted on select request
        const query = { _id: new ObjectId(id) };
        const option = { upsert: true };
        const updatedDoc = {
          $set: {
            Status: "Accepted",
          },
        };
        const result = await AdoptRequestCollection.updateOne(
          query,
          updatedDoc,
          option
        );

        //update the pets collection
        const filter = { _id: new ObjectId(petID) };
        const updatedPetCollection = {
          $set: {
            Adopted: true,
          },
        };

        const result1 = await PetsCollection.updateOne(
          filter,
          updatedPetCollection
        );
        res.send({ success: true });
      }
    });
    //---------------------------AdoptedRequest_delete
    app.patch("/AdoptedRequest_reject/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: {
          Status: "Rejected",
        },
      };
      const result = await AdoptRequestCollection.updateOne(query, update);
      res.send(result);
    });

    //------------------------get a single data
    app.get("/SelectPets/:id", verifyToken, async (req, res) => {
      const user_email = req.user_email; // take user from the verify token
      const id = req.params.id;
      const match = {
        Adopt_email: user_email.email,
        PetId: id,
      };
      const query = { _id: new ObjectId(id) };
      const result = await PetsCollection.findOne(query);

      const findAdoptRequest = await AdoptRequestCollection.findOne(match);
      let AdoptRequest = false;
      if (findAdoptRequest) {
        AdoptRequest = true;
      } else {
        AdoptRequest = false;
      }

      res.send({ result, AdoptRequest });
    });

    //------------------------ AcceptRequest
    app.get("/AcceptRequest/:email", verifyToken, async (req, res) => {
      const User_email = req.params.email;
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.limit);
      const query = { Author_email: User_email, Status: "Accepted" };

      const result = await AdoptRequestCollection.find(query)
        .skip(page * size)
        .limit(size)
        .toArray();

      res.send(result);
    });
    //------------------------ AdoptionRequest_delete
    app.delete("/AdoptionRequest_delete/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await AdoptRequestCollection.deleteOne(query);
      res.send(result);
    });
    //------------------------- RequestStatus
    app.get("/RequestStatus/:email", verifyToken, async (req, res) => {
      const User_email = req.params.email;
      const page = parseInt(req.query.page) || 0;
      const size = parseInt(req.query.limit) || 10;
      const query = { Adopt_email: User_email };
      const result = await AdoptRequestCollection.find(query)
        .skip(page * size)
        .limit(size)
        .toArray();

      res.send(result);
    });
    //-----------------------put data of update pets
    app.put("/updatePets/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const updatedPets = req.body;
      const filter = { _id: new ObjectId(id) };
      const options = { upsert: true };
      const updatedDoc = {
        $set: {
          petName: updatedPets.petName,
          petImg: updatedPets.petImg,
          imageDeleteUrl: updatedPets.imageDeleteUrl,
          age: updatedPets.age,
          location: updatedPets.location,
          category: updatedPets.category,
          shortDescription: updatedPets.shortDescription,
          longDescription: updatedPets.longDescription,
          Author_email: updatedPets.Author_email,
          Author_name: updatedPets.Author_name,
          post_Create_Time: updatedPets.post_Create_Time,
          Adopted: updatedPets.Adopted,
        },
      };
      const result = await PetsCollection.updateOne(
        filter,
        updatedDoc,
        options
      );
      res.send(result);
    });
    //----------------------------------Delete pet api with imgbb
    app.delete("/deletePets/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      //delete from imgbb
      const query = { _id: new ObjectId(id) };
      //delete from mongodb
      const result = await PetsCollection.deleteOne(query);
      res.send(result);
    });

    //-------------------------------Create Donation Api
    app.post("/CreateDonation", verifyToken, async (req, res) => {
      const donation = req.body;
      const result = await DonationCampaigns.insertOne(donation);
      res.send(result);
    });
    //-------------------------------Get Donation Api
    app.get("/donation_details/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await DonationCampaigns.findOne(query);
      res.send(result);
    });
    //--------------------Search the option
    app.get("/options", async (req, res) => {
      const query = { Adopted: false };
      const options = {
        projection: { _id: 0, petName: 1 },
      };
      const result = await PetsCollection.find(query, options).toArray();
      res.send(result);
    });
    // //-------------------------------Pet list Infinite Api
    app.get("/pets", async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const search = req.query.search || "";
      const category = req.query.category || "";
      const limit = parseInt(req.query.limit) || 1;
      const skip = (page - 1) * limit;
      const query = {
        petName: { $regex: search, $options: "i" },
        Adopted: false,
        category: { $regex: category, $options: "i" },
      };
      const result = await PetsCollection.find(query)
        .skip(skip)
        .limit(limit)
        .sort({ post_Create_Time: -1 })
        .toArray();
      res.send(result);
    });

    //-------------------------------Donation Infinite Api
    app.get("/donations", async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 1;
      const sortValue = req.query.sort == "Asc" ? 1 : -1;
      const skip = (page - 1) * limit;
      // Get the current date
      const currentDate = new Date();
      // Convert the current date to a comparable string format "DD,MM,YYYY"
      const currentDateString = `${String(currentDate.getDate()).padStart(
        2,
        "0"
      )},${String(currentDate.getMonth() + 1).padStart(
        2,
        "0"
      )},${currentDate.getFullYear()}`;
      // Construct MongoDB aggregation pipeline to convert and sort dates
      const pipeline = [
        {
          $match: {
            DonationLastDate: { $gte: currentDateString },
          },
        },
        {
          $addFields: {
            // Convert string "30,06,2024" to ISODate { $dateFromString: { dateString: "2024-06-30" } }
            convertedDate: {
              $dateFromString: {
                dateString: {
                  $concat: [
                    { $substr: ["$DonationLastDate", 6, 4] },
                    "-", // year
                    { $substr: ["$DonationLastDate", 3, 2] },
                    "-", // month
                    { $substr: ["$DonationLastDate", 0, 2] }, // day
                  ],
                },
              },
            },
          },
        },
        { $sort: { convertedDate: sortValue } },
        { $skip: skip },
        { $limit: limit },
      ];
      const result = await DonationCampaigns.aggregate(pipeline).toArray();
      res.send(result);
    });

    //-------------------------------DonationCamp details random data show
    app.get("/donation_details_random", async (req, res) => {
      // Get the current date
      const currentDate = new Date();
      // Convert the current date to a comparable string format "DD,MM,YYYY"
      const currentDateString = `${String(currentDate.getDate()).padStart(
        2,
        "0"
      )},${String(currentDate.getMonth() + 1).padStart(
        2,
        "0"
      )},${currentDate.getFullYear()}`;

      const result = await DonationCampaigns.aggregate([
        {
          $match: {
            pause: false,
            DonationLastDate: { $gte: currentDateString },
          },
        },
        {
          $addFields: {
            // Convert string "30,06,2024" to ISODate { $dateFromString: { dateString: "2024-06-30" } }
            convertedDate: {
              $dateFromString: {
                dateString: {
                  $concat: [
                    { $substr: ["$DonationLastDate", 6, 4] },
                    "-", // year
                    { $substr: ["$DonationLastDate", 3, 2] },
                    "-", // month
                    { $substr: ["$DonationLastDate", 0, 2] }, // day
                  ],
                },
              },
            },
          },
        },
        {
          $sample: { size: 3 },
        },
      ]).toArray();
      res.send(result);
    });
    //-------------------------------MyDonateDetails (My Donation)
    app.get("/MyDonateDetails/:email", verifyToken, async (req, res) => {
      const User_email = req.params.email;
      const page = parseInt(req.query.page) || 0;
      const size = parseInt(req.query.limit) || 10;
      const skip = page * size;
      const query = { user_email: User_email };
      const result = await DonateMoneyCollection.find(query)
        .skip(skip)
        .limit(size)
        .toArray();

      const update = [];
      for (let item of result) {
        const query = { _id: new ObjectId(item.DonationItem_ID) };
        const option = {
          projection: { _id: 0, PetName: 1, DonationImg: 1 },
        };
        const data = await DonationCampaigns.findOne(query, option);
        item.Petname = data.PetName;
        item.DonationImg = data.DonationImg;
        update.push(item);
      }

      res.send(update);
    });
    //---------------------------------MyDonateDetails_Count
    app.get("/MyDonateDetails_Count/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { user_email: email };
      const count = await DonateMoneyCollection.countDocuments(query);
      res.send({ count });
    });
    //-------------------------------donateInformation
    app.get("/donateInformation/:id", async (req, res) => {
      const id = req.params.id;
      const query = { DonationItem_ID: id };
      const result = await DonateMoneyCollection.find(query).toArray();
      res.send(result);
    });
    //---------------------------------MyDonateDelete
    app.delete("/MyDonateDelete/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const data = req.body;
      const paymentIntent = data.transaction_id;
      //cheack
      //Refund from Stripe
      // Create a refund
      const refund = await stripe.refunds.create({
        payment_intent: paymentIntent,
      });
      //update in refund collection
      const update = {
        ...data,
        refund: true,
        refundId: refund.id,
      };
      const result = await RefundCollection.insertOne(update);
      if (result.acknowledged) {
        // delete from donate money
        const query = { _id: new ObjectId(id) };
        const result = await DonateMoneyCollection.deleteOne(query);
        res.send(result);
      }
    });
    //-------------------------------Pause Patch
    app.patch("/MyDonation_Pause/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const response = await DonationCampaigns.findOne(query);
      const currentPause = response.pause;
      const update = {
        $set: {
          pause: !currentPause,
        },
      };
      const result = await DonationCampaigns.updateOne(query, update);
      res.send(result);
    });
    //-----------------------------------DonationCamp Update patch api
    app.patch("/UpdateDonation/:id", verifyToken, async (req, res) => {
      const data = req.body;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const options = { upsert: true };
      const updatedDoc = {
        $set: {
          PetName: data.PetName,
          MaxDonation: data.MaxDonation,
          DonationImg: data.DonationImg,
          shortDescription: data.shortDescription,
          longDescription: data.longDescription,
          DonationLastDate: data.DonationLastDate,
        },
      };
      const result = await DonationCampaigns.updateOne(
        query,
        updatedDoc,
        options
      );
      res.send(result);
    });

    //-------------------------------DonationCamp Update get api
    app.get("/DonationCamp_Update/:id", verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await DonationCampaigns.findOne(query);
      res.send(result);
    });

    //-------------------------------Get All Donation Api based on email
    app.get("/MyDonation/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.limit);

      const query = { Author_email: email };

      // Pagination
      const result = await DonationCampaigns.find(query)
        .skip(page * size)
        .limit(size)
        .toArray();
      let TotalAmount = 0;
      let Progress = 0;
      const UpdateResult = [];
      // Option for Donation
      const option = {
        projection: {
          _id: 0,
          amount: 1,
        },
      };
      for (const item of result) {
        const rules = {
          DonationItem_ID: item._id.toHexString(),
        };
        const ItemBasedDonation = await DonateMoneyCollection.find(
          rules,
          option
        ).toArray();

        if (ItemBasedDonation.length > 0) {
          ItemBasedDonation.map((amount) => {
            TotalAmount = TotalAmount + amount.amount;
          });
        }
        Progress = Math.round((TotalAmount / (item.MaxDonation * 100)) * 100);
        UpdateResult.push({ ...item, Progress });
        TotalAmount = 0;
        Progress = 0;
      }
      res.send(UpdateResult);
    });

    //-------------------------------findCollection
    app.get("/findCollection/:id", async (req, res) => {
      const id = req.params.id;
      const query = { DonationItem_ID: id };
      const option = {
        projection: {
          _id: 0,
          amount: 1,
        },
      };
      const result = await DonateMoneyCollection.find(query, option).toArray();
      if (result.length > 0) {
      }
      res.send(result);
    });
    //---------------------pagination all Donation based on email
    app.get("/MyDonationCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Author_email: email };
      const count = await DonationCampaigns.countDocuments(query);
      res.send({ count });
    });

    //-------------------Payment Stripe
    app.post("/create_payment_intent", verifyToken, async (req, res) => {
      const { price } = req.body;
      const amount = parseInt(price * 100);
      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({
        clientScript: paymentIntent.client_secret,
      });
    });

    //--------------------Payment Save to database
    app.post("/payment_history", verifyToken, async (req, res) => {
      const data = req.body;
      const result = await DonateMoneyCollection.insertOne(data);
      res.send(result);
    });

    //--------------------MyRefund
    app.get("/MyRefund/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.limit);
      const query = { user_email: email };
      const result = await RefundCollection.find(query)
        .skip(page * size)
        .limit(size)
        .toArray();
      res.send(result);
    });
    //----------------------MyRefundCount
    app.get("/MyRefundCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { user_email: email };
      const count = await RefundCollection.countDocuments(query);
      res.send({ count });
    });

    //-----------------------User Dashboard
    app.get("/petCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Author_email: email };
      const count = await PetsCollection.countDocuments(query);
      res.send({ count });
    });
    app.get("/AdoptCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Author_email: email };
      const count = await AdoptRequestCollection.countDocuments(query);
      res.send({ count });
    });
    app.get("/DonateCount/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { Author_email: email };
      const count = await DonationCampaigns.countDocuments(query);
      res.send({ count });
    });

    //--------------------------------User Dashboard Chart Data create
    app.get("/donationHistory/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      //find All Donation of user
      const query = { Author_email: email };
      const option = {
        projection: {
          _id: 1,
        },
      };
      const DonateID = await DonationCampaigns.find(query, option).toArray();
      let Donate = [];
      let refund = [];
      //find donate money based on DonateID
      for (const item of DonateID) {
        const query3 = { DonationItem_ID: item._id.toHexString() };
        const option3 = {
          projection: {
            _id: 0,
            amount: 1,
            user_name: 1,
            date: 1,
          },
        };
        const DonateData = await DonateMoneyCollection.find(
          query3,
          option3
        ).toArray();

        const RefundData = await RefundCollection.find(
          query3,
          option3
        ).toArray();

        for (const item of DonateData) {
          Donate.push(item);
        }
        for (const item of RefundData) {
          refund.push(item);
        }
      }
      //now combine all Donate data based on same date
      const combineDonate = [];
      const DonateDetails = [];
      let Total = 0;
      for (let item of Donate) {
        const date = item.date.split("T")[0];
        const data = Donate.some((item) => {
          if (item.date.split("T")[0] === date) {
            Total += item.amount;
          }
        });
        Total = Total / 100;
        combineDonate.push({ date: date, Donate: Total });
        DonateDetails.push({
          date: date,
          amount: item.amount / 100,
          user_name: item.user_name,
          refund: false,
        });
        Total = 0;
      }

      //now combine all Refund data based on same date
      for (let item of refund) {
        const date = item.date.split("T")[0];
        const data = refund.some((item) => {
          if (item.date.split("T")[0] === date) {
            Total += item.amount;
          }
        });
        Total = Total / 100;
        combineDonate.push({ date: date, Refund: Total });
        DonateDetails.push({
          date: date,
          amount: item.amount / 100,
          user_name: item.user_name,
          refund: true,
        });
        Total = 0;
      }
      //Remove Duplicate data
      const uniqueData = Array.from(
        new Set(combineDonate.map(JSON.stringify))
      ).map(JSON.parse);

      const combinedData = {};

      // Combine data based on date
      uniqueData.forEach((entry) => {
        const { date, Donate = 0, Refund = 0 } = entry;
        if (!combinedData[date]) {
          combinedData[date] = { date, Donate: 0, Refund: 0 };
        }
        combinedData[date].Donate += Donate;
        combinedData[date].Refund += Refund;
      });

      // Convert the combined data object back to an array
      const result = Object.values(combinedData);
      // Sort the result array by date
      result.sort((a, b) => new Date(a.date) - new Date(b.date));
      DonateDetails.sort((a, b) => new Date(b.date) - new Date(a.date));

      // Send the result as the response
      res.send({ result, DonateDetails });
    });
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close(); //if we want to connect with the server for life time then dont use this line
  }
}
run().catch(console.log);

app.get("/", (req, res) => {
  res.send("Home");
});
app.listen(port);
