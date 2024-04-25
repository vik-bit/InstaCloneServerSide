
const express = require('express')
const router = express.Router()
const mongoose = require('mongoose')
const User = mongoose.model("User")
const crypto = require('crypto')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cloudinary = require('cloudinary').v2;
const {JWT_SECRET} = require('../config/dev.js')
const requireLogin = require('../middleware/requireLogin')
require("dotenv").config();
const {EMAIL} = require('../config/keys');
const { domain } = require('process');
let API_KEY = process.env.API_KEY;
let DOMAIN = 'sandbox36ecff7885ce48a89c471e2b26346cd4.mailgun.org';
const mailgun = require('mailgun-js')({ apiKey: API_KEY, domain: DOMAIN });

sendMail = function (sender_email, receiver_email,
    email_subject, email_body) {
 
    const data = {
        "from": sender_email,
        "to": receiver_email,
        "subject": email_subject,
        "text": email_body
    };
 
    mailgun.messages().send(data, (error, body) => {
        if (error) console.log(error)
        else console.log(body);
    });
}
 
router.post('/signup',(req,res)=>{
  const {name,email,password,pic} = req.body 
  if(!email || !password || !name){
     return res.status(422).json({error:"please add all the fields"})
  }
  User.findOne({email:email})
  .then((savedUser)=>{
      if(savedUser){
        return res.status(422).json({error:"user already exists with that email"})
      }
      bcrypt.hash(password,12)
      .then(hashedpassword=>{
            const user = new User({
                email,
                password:hashedpassword,
                name,
                pic
            })
    
            user.save()
            .then(user=>{
               console.log(user.email);
               let sender_email = process.env.sender_email
               let receiver_email = user.email
               let email_subject = 'signup success'
               let email_body = 'welcome to instagram' 

               // User-defined function to send email
sendMail(sender_email, receiver_email,
    email_subject, email_body)
              
    res.json({message:"saved successfully"})
            })
            .catch(err=>{
                console.log(err)
            })
      })
     
  })
  .catch(err=>{
    console.log(err)
  })
})


router.post('/signin',(req,res)=>{
    const {email,password} = req.body
    if(!email || !password){
       return res.status(422).json({error:"please add email or password"})
    }
    User.findOne({email:email})
    .then(savedUser=>{
        if(!savedUser){
           return res.status(422).json({error:"Invalid Email or password"})
        }
        bcrypt.compare(password,savedUser.password)
        .then(doMatch=>{
            if(doMatch){
                // res.json({message:"successfully signed in"})
               const token = jwt.sign({_id:savedUser._id},JWT_SECRET)
               const {_id,name,email,followers,following,pic} = savedUser
               res.json({token,user:{_id,name,email,followers,following,pic}})
            }
            else{
                return res.status(422).json({error:"Invalid Email or password"})
            }
        })
        .catch(err=>{
            console.log(err)
        })
    })
})


router.post('/reset-password',(req,res)=>{
     crypto.randomBytes(32,(err,buffer)=>{
         if(err){
             console.log(err)
         }
         const token = buffer.toString("hex")
         User.findOne({email:req.body.email})
         .then(user=>{
             if(!user){
                 return res.status(422).json({error:"User dont exists with that email"})
             }
             user.resetToken = token
             user.expireToken = Date.now() + 3600000
             user.save().then((result)=>{
                
               
                let sender_email = process.env.sender_email
                let receiver_email = user.email
                let email_subject = 'password reset'
                let email_body = `click in this <a href="${process.env.EMAIL}/reset/${token}">link</a> to reset password` 
 
                // User-defined function to send email
 sendMail(sender_email, receiver_email,
     email_subject, email_body)

                
        })
         })
     })
})


router.post('/new-password',(req,res)=>{
    const newPassword = req.body.password
    const sentToken = req.body.token
    User.findOne({resetToken:sentToken,expireToken:{$gt:Date.now()}})
    .then(user=>{
        if(!user){
            return res.status(422).json({error:"Try again session expired"})
        }
        bcrypt.hash(newPassword,12).then(hashedpassword=>{
           user.password = hashedpassword
           user.resetToken = undefined
           user.expireToken = undefined
           user.save().then((saveduser)=>{
               res.json({message:"password updated success"})
           })
        })
    }).catch(err=>{
        console.log(err)
    })
})


module.exports = router