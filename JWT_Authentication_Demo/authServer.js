require('dotenv').config();

const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');

app.use(express.json());


let refreshTokens = []

app.post('/token',(rep,res) =>{

  console.log(rep.headers);
  
  const refreshToken = rep.body.token
  if(refreshToken == null) return res.sendStatus(401)
  if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403)

  jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET,(err,user) =>{
    if(err) return res.sendStatus(403)

    const accessToken = generateAccessToken({name: user.name})

    res.json({accessToken: accessToken})
  })

})

app.delete('/logout',(rep,res) =>{
  refreshTokens = refreshTokens.filter(token => token !== rep.body.token)
  res.sendStatus(204)
})  



app.post('/login',(rep,res) =>{


  const username = rep.body.username;
  const user = {name: username}

  const accessToken = generateAccessToken(user)
  const refreshToken = jwt.sign(user,process.env.REFRESH_TOKEN_SECRET)

  refreshTokens.push(refreshToken)


  res.json({accessToken: accessToken,refreshToken: refreshToken})

})


function generateAccessToken(user){
  return jwt.sign(user,process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
}

app.listen(4000)