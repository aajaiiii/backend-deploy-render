// create colletion กับ Document
const mongoose = require("mongoose");

const UserDetailsScehma = new mongoose.Schema(
  {
    username: { type: String, unique: true },
    name: String,
    surname: String,
    email: { type: String, unique: true },
    password: String,
    isEmailVerified: { type: Boolean, default: false }
  },
  {
    collection: "Admin",
    timestamps: true,
  }
);

mongoose.model("Admin", UserDetailsScehma);

const otpSchema = new mongoose.Schema({
  username: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: '10m' }
}, {
  collection: 'OTPModel'
});

mongoose.model("OTPModel", otpSchema);

const otpuserSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: '10m' }
}, {
  collection: 'OTPModelUser'
});

mongoose.model("OTPModelUser", otpuserSchema);

const equipmentScehma = new mongoose.Schema(
  {
    equipment_name: String,
    equipment_type: String,
    // admin:[{type: mongoose.Schema.Types.ObjectId,ref:'Admin'}]
  },
  {
    collection: "Equipment",
    timestamps: true,
  }
);

mongoose.model("Equipment", equipmentScehma);

const equipmentuserScehma = new mongoose.Schema(
  {
    equipmentname_forUser: String,
    equipmenttype_forUser: String,
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'

    }
  },
  {
    collection: "EquipmentUser",
    timestamps: true,
  }
);

mongoose.model("EquipmentUser", equipmentuserScehma);

const MPersonnelScehma = new mongoose.Schema(
  {
    username: { type: String, unique: true },
    password: String,
    email: { type: String, unique: true },
    tel: String,
    nametitle: String,
    name: String,
    surname: String,
    isEmailVerified: { type: Boolean, default: false }
  },
  {
    collection: "MPersonnel",
    timestamps: true,
  }
);

mongoose.model("MPersonnel", MPersonnelScehma);

const CaremanualScehma = new mongoose.Schema(
  {
    caremanual_name: String,
    image: String,
    file: String,
    detail: String,
    views: { type: Number, default: 0 },
    originalFileName: {
      type: String,
      required: false,
    },
  },
  {
    collection: "Caremanual",
    timestamps: true,
  }
);

mongoose.model("Caremanual", CaremanualScehma);

//ผู้ป่วย
const UserScehma = new mongoose.Schema(
  {
    username: { type: String, unique: true },
    password: String,
    email: { type: String, sparse: true },
    tel: String,
    originalTel: { type: String, required: false }, 
    name: String,
    surname: String,
    gender: String,
    birthday: Date,
    ID_card_number: String,
    nationality: String,
    Address: String,
    acceptPDPA: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
    deleteExpiry:  { type: Date, default: null },
    AdddataFirst: { type: Boolean, default: false },
    AdddataFirst: { type: Boolean, default: false },
    physicalTherapy: { type: Boolean, default: false },
    isEmailVerified: { type: Boolean, default: false }
  },
  {
    collection: "User",
    timestamps: true,
  }
);

mongoose.model("User", UserScehma);

//ผู้ดูแล
const CaregiverScehma = new mongoose.Schema(
  {
    ID_card_number: String,
    name: String,
    surname: String,
    // Relationship: String,
    tel: String,
    userRelationships: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        relationship: String,
      },
    ],
    // user: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // เปลี่ยนเป็น array
    // user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  {
    collection: "Caregiver",
    timestamps: true,
  }
);

mongoose.model("Caregiver", CaregiverScehma);

//อาการ
const SymptomScehma = new mongoose.Schema(
  {
    name: String,
  },
  {
    collection: "Symptom",
    timestamps: true,
  }
);

mongoose.model("Symptom", SymptomScehma);

//ข้อมูลการเจ็บป่วย
const MedicalInformationSchema = new mongoose.Schema(
  {
    HN: String,
    AN: String,
    Date_Admit: Date,
    Date_DC: Date,
    Diagnosis: String,
    Chief_complaint: String,
    Present_illness: String,
    selectedPersonnel: String,
    Phychosocial_assessment: String,
    Management_plan: String,
    fileM: String,
    fileP: String,
    filePhy: String,
    fileMName: {
      type: String,
      required: false, // ถ้าไม่บังคับอัปโหลดไฟล์
    },
    filePName: {
      type: String,
      required: false,
    },
    filePhyName: {
      type: String,
      required: false,
    },
    
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // แก้เป็น ref: "User"
    // equipment: { type: mongoose.Schema.Types.ObjectId, ref: "Equipment" },
    // personnel: { type: mongoose.Schema.Types.ObjectId, ref: "MPersonnel" },
  },
  {
    collection: "MedicalInformation",
    timestamps: true,
  }
);
mongoose.model("MedicalInformation", MedicalInformationSchema);

//ฟอร์มบันทึกอาการ
const PatientFormSchema = new mongoose.Schema(
  {
    Symptoms: [String],
    SBP: Number,
    DBP: Number,
    PulseRate: Number,
    Temperature: Number,
    DTX: Number,
    Respiration: Number,
    LevelSymptom: String,
    Painscore: Number,
    request_detail: String,
    Recorder: String,
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

  },
  {
    collection: "PatientForm",
    timestamps: true,
  }
);

mongoose.model("PatientForm", PatientFormSchema);


const AssessmentScehma = new mongoose.Schema(
  {
    suggestion: String,
    detail: String,
    status_name: String,
    PPS: Number,
    MPersonnel: { type: mongoose.Schema.Types.ObjectId, ref: "MPersonnel" },
    PatientForm: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PatientForm",
      unique: true,
    },
    history: [
      {
        suggestion: String,
        detail: String,
        status_name: String,
        PPS: Number,
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "MPersonnel" },
        updatedAt: { type: Date, default: Date.now },
      },
    ],  
  },
  {
    collection: "Assessment",
    timestamps: true,
  }
);

mongoose.model("Assessment", AssessmentScehma);


// const chatSchema = new mongoose.Schema(
//   {
//     message: String,
//     sender: {
//       type: mongoose.Schema.Types.ObjectId,
//       refPath: 'senderModel',
//     },
//     image: String,
//     imageName: {
//       type: String,
//       default: null,
//     },
//     recipientIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'MPersonnel' }], 
//     recipient: {
//       type: mongoose.Schema.Types.ObjectId,
//       refPath: 'recipientModel',
//     },
//     senderModel: {
//       type: String,
//       required: true,
//       enum: ['User', 'MPersonnel'],
//     },
//     recipientModel: {
//       type: String,
//       // required: true,
//       enum: ['User', 'MPersonnel'],
//     },
//     isRead: {
//       type: Boolean,
//       default: false
//     },
//     readAt: Date,
//     readBy: [
//       {
//         type: mongoose.Schema.Types.ObjectId,
//         refPath: 'recipientModel',
//       },
//     ],
//     fileSize: {
//       type: Number, 
//       default: null,
//     },
//   },

//   {
//     collection: "Chat",
//     timestamps: true,
//   }
// );

// mongoose.model("Chat", chatSchema);

const chatSchema = new mongoose.Schema(
  {
    message: String,
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      refPath: 'senderModel',
    },
    image: String,
    imageName: {
      type: String,
      default: null,
    },
    roomId: {
      type: mongoose.Schema.Types.ObjectId, // เก็บ userId ตามที่อธิบายไว้
      required: true,
    },
    senderModel: {
      type: String,
      required: true,
      enum: ['User', 'MPersonnel'],
    },
    isRead: {
      type: Boolean,
      default: false,
    },
    readAt: Date,
    readBy: [
      {
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'senderModel',
      },
    ],
    fileSize: {
      type: Number,
      default: null,
    },
  },
  {
    collection: 'Chat',
    timestamps: true,
  }
);
chatSchema.index({ roomId: 1, readBy: 1 }); 
mongoose.model('Chat', chatSchema);

const RoomSchema = new mongoose.Schema({
  roomId: mongoose.Schema.Types.ObjectId,
  deletedAt: { type: Date, default: null },
  participants: [
    {
      id: mongoose.Schema.Types.ObjectId,
      model: { type: String, enum: ["User", "MPersonnel"] },
      unreadCount: { type: Number, default: 0 }, // จำนวนแชทที่ยังไม่ได้อ่านสำหรับผู้ใช้
    },  
  ],
},
  {
    collection: 'Room',
    timestamps: true,
  }
);
mongoose.model('Room', RoomSchema);

const AlertSchema = new mongoose.Schema(
  {
    patientFormId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PatientForm",
      required: true
    },
    alertMessage: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    createdAtAss: {
      type: Date,
      // ลบ default: Date.now ออกไป เพราะจะใช้ค่า createdAt ที่ส่งจาก Assessment
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    MPersonnel: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "MPersonnel",
      required: false, 
    },
    alertType: { // ✅ เพิ่มฟิลด์นี้
      type: String,
      enum: ["abnormal", "normal", "assessment"], // ✅ กำหนดค่าที่เป็นไปได้
      required: true
    },
    viewedBy: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: "MPersonnel"
    }]
  },
  {
    collection: "Alert",
    timestamps: true,
  }
);

mongoose.model("Alert", AlertSchema);


const NotificationSchema = new mongoose.Schema(
  {
    patientFormId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PatientForm",
      required: true
    },
    alertMessage: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    createdAtAss: {
      type: Date,
      // ลบ default: Date.now ออกไป เพราะจะใช้ค่า createdAt ที่ส่งจาก Assessment
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    viewedBy: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: "MPersonnel"
    }]
  },
  {
    collection: "Notification",
    timestamps: true,
  }
);

mongoose.model("Notification", NotificationSchema);


const UserThresholdSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  SBP: { min: Number, max: Number },
  DBP: { min: Number, max: Number },
  PulseRate: { min: Number, max: Number },
  Temperature: { min: Number, max: Number },
  DTX: { min: Number, max: Number },
  Respiration: { min: Number, max: Number },
  Painscore: { type: Number}
}, {
  collection: 'UserThresholds',
  timestamps: true,
});

mongoose.model('UserThreshold', UserThresholdSchema);

const ReadinessFormSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  MPersonnel: { type: mongoose.Schema.Types.ObjectId, ref: "MPersonnel" },
  Readiness1: {
    question1_1: { type: String, required: true },
    question1_2: { type: String, required: true },
    question1_3: { type: String, required: true },
    question1_4: { type: String, required: true },
  },
  Readiness2: {
    Disease: { type: String, required: true },
    Medication: { type: String, required: true },
    Environment: { type: String, required: true },
    Treatment: { type: String, required: true },
    Health: { type: String, required: true },
    Out_patient: { type: String, required: true },
    Diet: { type: String, required: true },
  },
  status_name: String,
}, {
  collection: 'ReadinessForm',
  timestamps: true,
});

mongoose.model('ReadinessForm', ReadinessFormSchema);

const ReadinessAssessmentSchema = new mongoose.Schema({
  ReadinessForm: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "ReadinessForm",
    required: true
  },
  MPersonnel: { type: mongoose.Schema.Types.ObjectId, ref: "MPersonnel" },
  readiness_status: String,
  detail: String,
}, {
  collection: 'ReadinessAssessment',
  timestamps: true,
});

mongoose.model('ReadinessAssessment', ReadinessAssessmentSchema);


const AssessinhomesssSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  MPersonnel: { type: mongoose.Schema.Types.ObjectId, ref: "MPersonnel" },
  Caregiver: [{ type: mongoose.Schema.Types.ObjectId, ref: "Caregiver" }],
  Immobility:
  {
    Pick_up_food: { type: Number, required: true },
    Clean_up: { type: Number, required: true },
    Put_on_clothes: { type: Number, required: true },
    Shower: { type: Number, required: true },
    Using_the_toilet: { type: Number, required: true },
    Get_up: { type: Number, required: true },
    Walk_inside: { type: Number, required: true },
    Up_down_stairs: { type: Number, required: true },
    Continence_urine: { type: Number, required: true },
    Continence_stool: { type: Number, required: true },
    Walk_outside: { type: Number, required: true },
    Cooking: { type: Number, required: true },
    Household_chores: { type: Number, required: true },
    Shopping: { type: Number, required: true },
    Taking_public_transportation: { type: Number, required: true },
    Taking_medicine: { type: Number, required: true },
    totalScore: { type: Number, required: true }
  },
  Nutrition: {
    gender: { type: String, default: "" }, // เพิ่มเพศ
    userAge: { type: Number, default: 0 }, // อายุในปี
    userAgeInMonths: { type: Number, default: 0 }, // อายุในเดือน
    weight: { type: Number, default: 0 },
    height: { type: Number, default: 0 },
    bmr: { type: Number, default: "" },
    tdee: { type: Number, default: "" },
    activityLevel: { type: String, default: "" },
    intakeMethod: [{ type: String, default: "" }], // Array of strings
    foodTypes: [{ type: String, default: "" }], // Array of strings
    medicalFood: { type: String, default: "" },
    favoriteFood: { type: String, default: "" },
    cooks: [{ type: String, default: "" }], // Array of strings
    nutritionStatus: { type: String, default: "" },
  },
  Housing: {
    houseType: { type: String, default: "" },
    material: { type: String, default: "" },
    numFloors: { type: String, default: "" },
    numRooms: { type: String, default: "" },
    patientFloor: { type: String, default: "" },
    cleanliness: { type: String, default: "" },
    orderliness: { type: String, default: "" },
    lighting: { type: String, default: "" },
    ventilation: { type: String, default: "" },
    homeEnvironment: [{ type: String, default: "" }],
    homeEnvironment_petType: { type: String, default: "" },
    otherHomeEnvironment: { type: String, default: "" },
    neighborRelationship: { type: String, default: "" },
    numneighbor: { type: String, default: "" },
    neighborHelp: { type: String, default: "" },
  },
  OtherPeople: {
    existingCaregivers: [{
      CaregiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'Caregiver' }, // อ้างอิง caregiver ที่มีอยู่
      firstName: { type: String, default: "" }, // เพิ่มฟิลด์นี้
      lastName: { type: String, default: "" },  // เพิ่มฟิลด์นี้
      birthDate: { type: String, default: "" },
      relationship: { type: String, default: "" },
      occupation: { type: String, default: "" },
      status: { type: String, default: "" },
      education: { type: String, default: "" },
      income: { type: String, default: "" },
      benefit: { type: String, default: "" },
      ud: { type: String, default: "" },
      habit: { type: String, default: "" },
      careDetails: { type: String, default: "" },
      // isNew: { type: Boolean, default: false },
    }],
    newCaregivers: [{
      firstName: { type: String, default: "" },
      lastName: { type: String, default: "" },
      birthDate: { type: String, default: "" },
      relationship: { type: String, default: "" },
      occupation: { type: String, default: "" },
      status: { type: String, default: "" },
      education: { type: String, default: "" },
      income: { type: String, default: "" },
      benefit: { type: String, default: "" },
      ud: { type: String, default: "" },
      habit: { type: String, default: "" },
      careDetails: { type: String, default: "" },
      // isNew: { type: Boolean, default: true },
    }],
  },
  Medication: {
    prescribedMedication: { type: String, default: "" },
    actualMedication: { type: String, default: "" },
    supplements: { type: String, default: "" },
    administration: { type: String, default: "" },
    intake: { type: String, default: "" },
    consistency: { type: String, default: "" },
  },
  PhysicalExamination: {
    temperature: { type: Number, default: null },
    bloodPressure: { type: String, default: "" },
    pulse: { type: Number, default: null },
    respiratoryRate: { type: Number, default: null },
    generalAppearance: { type: String, default: "" },
    cardiovascularSystem: { type: String, default: "" },
    respiratorySystem: { type: String, default: "" },
    abdominal: { type: String, default: "" },
    nervousSystem: { type: String, default: "" },
    extremities: { type: String, default: "" },
    moodandaffect: [
      {
        value: { type: String, default: "" }, // ตัวเลือกที่เลือก
        isOther: { type: Boolean, default: false },
         _id: false // ระบุว่าเป็น "อื่นๆ" หรือไม่
      }
    ],
    appearanceAndBehavior: [
      {
        value: { type: String, default: "" },
        isOther: { type: Boolean, default: false },
         _id: false
      }
    ],
    eyeContact: [
      {
        value: { type: String, default: "" },
        isOther: { type: Boolean, default: false },
         _id: false
      }
    ],
    attention: [
      {
        value: { type: String, default: "" },
        isOther: { type: Boolean, default: false },
         _id: false
      }
    ],
    orientation: [
      {
        value: { type: String, default: "" },
        isOther: { type: Boolean, default: false },
         _id: false
      }
    ],
    thoughtProcess: [
      {
        value: { type: String, default: "" },
        isOther: { type: Boolean, default: false },
         _id: false
      }
    ],
    thoughtContent: [
      {
        value: { type: String, default: "" },
        isOther: { type: Boolean, default: false },
         _id: false
      }
    ],
  },
  SSS: {
    Safety: {
      cleanliness: { type: String, default: "" },
      floorSafety: { type: String, default: "" },
      stairsSafety: { type: String, default: "" },
      handrailSafety: { type: String, default: "" },
      sharpEdgesSafety: { type: String, default: "" },
      slipperyFloorSafety: { type: String, default: "" },
      toiletSafety: { type: String, default: "" },
      stoveSafety: { type: String, default: "" },
      storageSafety: { type: String, default: "" },
      waterSafety: { type: String, default: "" },
      otherHealthHazards: { type: String, default: "" },
      emergencyContact: { type: String, default: "" },
    },
    SpiritualHealth: {
      faithBelief: { type: String, default: "" },
      importance: { type: String, default: "" },
      community: { type: String, default: "" },
      addressInCare: { type: String, default: "" },
      love: { type: String, default: "" },
      religion: { type: String, default: "" },
      forgiveness: { type: String, default: "" },
      hope: { type: String, default: "" },
      meaningOfLife: { type: String, default: "" },
    },
    Service: {
      serviceLocation: { type: String, default: "" },
      otherServices: { type: String, default: "" },
    },
  },
  status_inhome: String,
}, {
  collection: 'Assessinhomesss',
  timestamps: true,
});
mongoose.model('Assessinhomesss', AssessinhomesssSchema);

const AgendaSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  MPersonnel: { type: mongoose.Schema.Types.ObjectId, ref: "MPersonnel" },
  Caregiver: [{ type: mongoose.Schema.Types.ObjectId, ref: "Caregiver" }],
  newCaregivers: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assessinhomesss" }],
  PatientAgenda: {
    patient_idea: { type: String, default: "" },
    patient_feeling: { type: String, default: "" },
    patient_funtion: { type: String, default: "" },
    patient_expectation: { type: String, default: "" },
  },
  CaregiverAgenda: {
    Old_Caregiver_Agenda: [{   
      firstName: { type: String, default: "" },
      lastName: { type: String, default: "" },
      relationship: { type: String, default: "" },
      caregiver_idea: { type: String, default: "" },
      caregiver_feeling: { type: String, default: "" },
      caregiver_function: { type: String, default: "" },
      caregiver_expectation: { type: String, default: "" },
    }],

    New_Caregiver_Agenda: [{  
      firstName: { type: String, default: "" },
      lastName: { type: String, default: "" },
      relationship: { type: String, default: "" },
      caregiver_idea: { type: String, default: "" },
      caregiver_feeling: { type: String, default: "" },
      caregiver_function: { type: String, default: "" },
      caregiver_expectation: { type: String, default: "" },
    }],
  },

  CaregiverAssessment: {
    Old_Caregiver_Assessment: [{  
      firstName: { type: String, default: "" },
      lastName: { type: String, default: "" },
      relationship: { type: String, default: "" },
      care: { type: String, default: "" },
      affection: { type: String, default: "" },
      rest: { type: String, default: "" },
      empathy: { type: String, default: "" },
      goalOfCare: { type: String, default: "" },
      information: { type: String, default: "" },
      ventilation: { type: String, default: "" },
      empowerment: { type: String, default: "" },
      resource: { type: String, default: "" },
    }],

    New_Caregiver_Assessment: [{  
      firstName: { type: String, default: "" },
      lastName: { type: String, default: "" },
      relationship: { type: String, default: "" },
      care: { type: String, default: "" },
      affection: { type: String, default: "" },
      rest: { type: String, default: "" },
      empathy: { type: String, default: "" },
      goalOfCare: { type: String, default: "" },
      information: { type: String, default: "" },
      ventilation: { type: String, default: "" },
      empowerment: { type: String, default: "" },
      resource: { type: String, default: "" },
    }],
  },
  Zaritburdeninterview: {
    question_1: { type: Number, required: true },
    question_2: { type: Number, required: true },
    question_3: { type: Number, required: true },
    question_4: { type: Number, required: true },
    question_5: { type: Number, required: true },
    question_6: { type: Number, required: true },
    question_7: { type: Number, required: true },
    question_8: { type: Number, required: true },
    question_9: { type: Number, required: true },
    question_10: { type: Number, required: true },
    question_11: { type: Number, required: true },
    question_12: { type: Number, required: true },
    totalScore: { type: Number, required: true }
  },
  status_agenda: String,
}, {
  collection: 'Agenda',
  timestamps: true,
});
mongoose.model('Agenda', AgendaSchema);

AssessinhomesssSchema.post('save', async function (doc, next) {
  const Agenda = mongoose.model('Agenda');
  const newCaregiverIds = doc.OtherPeople.newCaregivers.map(cg => cg._id);

  try {
    // Update Agenda collection by adding newCaregiver IDs
    await Agenda.updateMany(
      { user: doc.user, MPersonnel: doc.MPersonnel },
      { $addToSet: { newCaregivers: { $each: newCaregiverIds } } } // อัปเดต newCaregivers
    );
    next();
  } catch (error) {
    next(error);
  }
});

const DefaultThresholdSchema = new mongoose.Schema({
  SBP: { min: Number, max: Number },
  DBP: { min: Number, max: Number },
  PulseRate: { min: Number, max: Number },
  Temperature: { min: Number, max: Number },
  DTX: { min: Number, max: Number },
  Respiration: { min: Number, max: Number },
  Painscore: { type: Number},
},  {
  collection: 'DefaultThreshold',
  timestamps: true,
});

mongoose.model('DefaultThreshold', DefaultThresholdSchema);


