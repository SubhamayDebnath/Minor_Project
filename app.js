import express from "express";
import morgan from "morgan";
import { config } from "dotenv";
import expressLayout from "express-ejs-layouts";
import methodOverride from "method-override";
import cookieParser from "cookie-parser";
import session from "express-session";
import flush from "connect-flash";
import MongoStore from "connect-mongo";
config();

import mainRoutes from './server/routes/main/main.routes.js'

const app = express();
const PORT = process.env.PORT;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(methodOverride("_method"));
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB,
    }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
  })
);
app.use(express.static("public"));
app.use(expressLayout);
app.set("layout", "./layouts/main");
app.set("view engine", "ejs");

app.use(flush());
app.use(morgan("dev"));
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  next();
});

app.use("",mainRoutes);
app.use("*", (req, res) => {
  res.status(404).send("Page Not Found");
});

app.listen(PORT, async () => {
  console.log(`server is running on port http://localhost:${PORT}`);
});