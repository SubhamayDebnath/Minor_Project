/*
  Home Page 
*/
const homePage = async (req, res) => {
  try {
    res.render("index");
  } catch (error) {
    console.log(`Home Page Error: ${error}`);
    res.redirect(500,"/error");
  }
};

/*
  Error Page 
*/
const utilsLayout = "../views/layouts/utils";
const errorPage = async (req, res) => {
  res.render("error/error", {
    locals: { title: "Error", description: "Error page" },
    layout: utilsLayout,
  });
};
export { homePage, errorPage };
