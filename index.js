import express, { request, response } from "express";
import { ConnectionClosedEvent, MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";
import { getallusers, addusers, searchbyuser ,addRandomNumber,searchbyuserInReset,updatePassword} from "./helper.js";
import { auth } from "./middleware/auth.js";

import nodemailer from "nodemailer";



import localStorage from "localStorage"

const app = express();
dotenv.config();

//middlewares//
app.use(cors());
app.use(express.json());

//loading data from hidden env

// const GMAIL_PASSWORD=process.env.GMAIL_PASSWORD

const PORT = process.env.PORT
const MONGO_URL = process.env.MONGO_URL
const SECRET_KEY=process.env.SECRET_KEY
const GMAIL_PASSWORD=process.env.GMAIL_PASSWORD

app.listen(PORT, () => console.log("Server Started"));

app.get("/", (request, response) => {
    response.send("Hello from express JS")
})


export async function createConnection() {
    const client = new MongoClient(MONGO_URL);
    await client.connect();
    return client;
}

app.get("/login" ,async (request, response) => {
    const result = await getallusers();
    response.send(result)
})

app.post("/login", async (request, response) => {
    const { EmailId, Password } = request.body;
    const user = await searchbyuser(EmailId)
    
    if (user) {
        console.log(user)
        const dbPassword = user.Password;
        const loginPassword = Password;
        const isPassMatched = await bcrypt.compare(loginPassword, dbPassword);
        if(isPassMatched){
            const jtoken=jwt.sign({id:user._id},SECRET_KEY)
            
            response.send({message: "Successfull Login",token:jtoken,id:user._id,loggedin:true})
        }
        else
            response.send({message: "Invalid Credentials",loggedin:false})
    }
    else    
        response.send({message: "Invalid Credentials",loggedin:false})
})

async function generatePassword(password) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt)
    return (hashedPassword)
}

app.post("/signup", async (request, response) => {
    const { FirstName, LastName, EmailId, Password} = request.body;
    const hashedPassword = await generatePassword(Password)
    const result = await addusers(FirstName, LastName, EmailId, hashedPassword);
    response.send(result)
})


app.get("/content",auth,async(request,response)=>{
    response.send("Protected content")
})




app.post("/userExist", async (request, response) => {
    const { EmailId} = request.body;
    // console.log(EmailId)

    const user = await searchbyuser(EmailId)

    if (user){
        const randomNum=Math.floor(100000 + Math.random() * 900000)
        // console.log(randomNum)
        addRandomNumber(EmailId,randomNum)
        
    }
    if (user) {
            response.send({message: "User Exist",EmailId,flag:true})
    }
    else    
        response.send({message: "User Does not exist",flag:false})
})

app.post("/verfiyResetCode", async (request, response) => {
    const { EmailId} = request.body;
    console.log(EmailId)

    const user = await searchbyuserInReset(EmailId)
    if (user){
        response.send(user)
    }
    else    
        response.send({message: "User does not exist",flag:false})
})


app.post("/setNewPassword", async (request, response)=>{
    const {EmailId,Password}=request.body;
    const hashedPassword = await generatePassword(Password)
    const k=await updatePassword(EmailId,hashedPassword)
    response.send(k)
})

app.post("/sendmail",async(request,response)=>{
    const values=request.body;
    const client=await createConnection()
    
    var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              user: 'testerAtwork09@gmail.com',
              pass: GMAIL_PASSWORD
            }
          });
          
          var mailOptions = {
            from: 'testerAtwork09@gmail.com',
            to: "kaustubhmagdum@gmail.com",
            subject: 'contact page says',
            text: `${values.firstName} ${values.lastName} says ${values.message}
             can contact me on ${values.emailId}`
          };

          transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                console.log(error);
                 response.send({success:false,result:info.response})
            } else {
              console.log('Email sent: ' + info.response);
                response.send({success:true,result:info.response})
            }
          });
    
    
    
  })














