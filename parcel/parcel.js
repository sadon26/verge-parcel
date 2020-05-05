const express = require("express");
const router = express.Router();
const pool = require("../query");
const verify = require("../auth/verifyToken")

//Create a new parcel
//Route api/v1/parcel
router.post(
  "/", verify,
  async (req, res, next) => {
    const {
      id
    } = req.body;

    const queryObj = {
      text: "SELECT * FROM Users WHERE role_id = $1",
      values: [id],
    };

    await pool.query(queryObj, (err, results) => {
      const user = results.rows[0]
      if (err) {
        throw err;
      }

      if (id !== 1) {
        res.status(404).json({
          message: "User not found",
        });
      }

      if (results.rowCount > 0 && id == 1) {
        next();
      } else {
        res.status(400).json({
          message: "User is not registered. Please sign up",
        });
      }
    });
  },
  async (req, res) => {
    const {
      price,
      weight,
      location,
      destination,
      sender_name,
      sender_note,
      status,
    } = req.body;
    let queryObjTwo = {
      text: "INSERT INTO parcel( price, weight, location, destination, sender_name, sender_note) VALUES ( $1, $2, $3, $4, $5, $6 ) RETURNING *",
      values: [price, weight, location, destination, sender_name, sender_note],
    };
    pool.query(queryObjTwo, (err, results) => {
      if (err) {
        throw err;
      }
      res.status(200).json({
        message: "Your parcel has been created successfully",
      });
    });
  }
);

//Get all parcels by user
//Route api/v1/parcel/
router.get(
  "/", verify,
  async (req, res, next) => {
    const {
      id
    } = req.body;
    pool.query(
      "SELECT * FROM Users WHERE role_id = $1",
      [id],
      (err, results) => {
        if (err) {
          throw err;
        }

        if (results.rowCount == 0) {
          res.status(400).json({
            message: "You have to be a user to view the list of parcels",
          });
        }
        if (id !== 1) {
          res.json({
            message: "User not found",
          });
        } else if (id == 1) {
          next();
        }
      }
    );
  },
  async (req, res) => {
    const {
      user_id
    } = req.body;
    pool.query(
      "SELECT * FROM parcel WHERE user_id = $1",
      [user_id],
      (err, results) => {
        if (err) {
          throw err;
        }
        if (results.rowCount == 0) {
          res.json({
            message: "User has not created any parcel yet"
          });
        }
        if (results.rowCount == 1) {
          res.json(results.rows);
        }
      }
    );
  }
);

//Get a parcel by id
//Route api/v1/parcel/:id
router.get(
  "/:id",
  async (req, res, next) => {
    const {
      id
    } = req.body;
    pool.query("SELECT * FROM Users WHERE id = $1", [id], (err, results) => {
      if (err) {
        throw err;
      }

      if (results.rowCount <= 0) {
        res.status(400).json({
          message: "You have to be a user to view parcel",
        });
      } else {
        next();
      }
    });
  },
  (req, res) => {
    const {
      id
    } = req.params;
    pool.query(
      "SELECT * FROM Parcel WHERE user_id = $1",
      [id],
      (err, results) => {
        if (results.rowCount == 0) {
          res.status(400).json({
            message: "You have not created any parcel yet",
          });
        }
        if (results.rowCount > 0) {
          res.json(results.rows[0]);
        }
      }
    );
  }
);

//Update a parcel by id
//Route api/v1/parcel/destination/change/:id
router.put(
  "/destination/change/:id",
  (req, res, next) => {
    const {
      id
    } = req.body;
    pool.query("SELECT * FROM Roles WHERE id = $1", [id], (err, results) => {
      if (err) {
        throw err;
      }
      if (results.rowCount <= 0) {
        res.status(400).json({
          message: "You are not authorised to change the destination of the parcel",
        });
      }
      if (id == 1) {
        next();
      } else {
        res.status(400).json({
          message: "Only users can change the destination of their parcel",
        });
      }
    });
  },
  (req, res) => {
    const {
      id
    } = req.params;
    const {
      destination,
      user_id
    } = req.body;
    pool.query(
      "SELECT * FROM parcel WHERE user_id = $1",
      [user_id],
      (err, results) => {
        const user = results.rows[0];
        if (results.rowCount == 0) {
          res.status(404).json({
            message: "User not found"
          });
        }
        if (user.status == "Pending") {
          pool.query(
            "UPDATE Parcel SET destination = $1 WHERE user_id = $2",
            [destination, id],
            (err, results) => {
              if (err) {
                throw err;
              }
              res.status(200).json({
                message: "Destination has been updated successfully",
              });
            }
          );
        } else if (user.status != "Pending") {
          res.json({
            message: "You can't update the status of your order because it has already been marked as delivered",
          });
        }
      }
    );
  }
);

router.delete(
  "/cancel/:id",
  (req, res, next) => {
    const {
      id
    } = req.body;
    pool.query("SELECT * FROM Users WHERE id = $1", [id], (err, results) => {
      if (err) {
        throw err;
      }
      if (results.rowCount <= 0) {
        res.status(400).json({
          message: "You are not authorised to delete parcel",
        });
      }
      next();
    });
  },
  (req, res) => {
    const {
      id
    } = req.params;
    pool.query(
      "DELETE FROM Parcel WHERE user_id = $1",
      [id],
      (err, results) => {
        if (err) {
          throw err;
        }
        res.status(200).json({
          message: "Parcel has been deleted successfully",
        });
      }
    );
  }
);

//Change status by admin
router.put(
  "/status/change/:id",
  async (req, res, next) => {
    const {
      id
    } = req.body;
    pool.query("SELECT * FROM Roles WHERE id = $1", [id], (err, results) => {
      if (err) {
        res.json({
          message: "Something went wrong",
        });
      }

      if (results.rows <= 0 || id > 2) {
        res.status(400).json({
          message: "You have to be registered as an admin to change the status of a parcel",
        });
      }

      if (id == 1) {
        res.status(400).json({
          message: "Users can't change the status of a parcel",
        });
      } else if (id == 2) {
        next();
      }
    });
  },
  (req, res) => {
    const {
      id
    } = req.params;
    const {
      status
    } = req.body;
    pool.query(
      "UPDATE Parcel SET status = $1 WHERE user_id = $2",
      [status, id],
      (err, results) => {
        if (err) {
          throw err;
        }
        res.json({
          message: "status has been updated successfully",
        });
      }
    );
  }
);

//Change location by admin
router.put(
  "/location/change/:id",
  async (req, res, next) => {
    const {
      id
    } = req.body;
    pool.query("SELECT * FROM Roles WHERE id = $1", [id], (err, results) => {
      if (err) {
        res.json({
          message: "Something went wrong",
        });
      }

      if (results.rows <= 0 || id > 2) {
        res.status(400).json({
          message: "You have to be registered as an admin to change the location of a parcel",
        });
      }

      if (id == 1) {
        res.status(400).json({
          message: "Users can't change the location of a parcel",
        });
      } else if (id == 2) {
        next();
      }
    });
  },
  (req, res) => {
    const {
      id
    } = req.params;
    const {
      location
    } = req.body;
    if (!location) {
      res.status(200).json({
        message: "Please add location",
      });
    }
    pool.query(
      "UPDATE Parcel SET location = $1 WHERE user_id = $2",
      [location, id],
      (err, results) => {
        if (err) {
          throw err;
        }
        res.json({
          message: "Location has been updated successfully",
        });
      }
    );
  }
);

module.exports = router;