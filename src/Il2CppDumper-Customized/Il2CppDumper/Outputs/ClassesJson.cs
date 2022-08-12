using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Il2CppDumper
{
    public class ClassesJson
    {

        public List<ScriptClasses> ScriptClassess = new List<ScriptClasses>();
    }


    public class ScriptClasses
    {
        public string NameSpace;
        public string Name;
        public List<string> Extends = new List<string>();
        public List<ScriptFields> ScriptFields = new List<ScriptFields>();
        public List<ScriptMethods> ScriptMethods = new List<ScriptMethods>();
    }
    public class ScriptFields
    {
        public int Offset;
        public string Name;
        public string Class;
    }
    public class ScriptMethods
    {
        public ulong Address;
        public string Name;
        public string ReturnType;
        public List<ScriptParameters> ScriptParameters = new List<ScriptParameters>();
    }
    public class ScriptParameters
    {
        public int Index;

        public string Name ="";
        public string ClassType;
    }

}
