﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace AleCGN.Security.Cryptography.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "17.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class LibraryResources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal LibraryResources() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("AleCGN.Security.Cryptography.Resources.LibraryResources", typeof(LibraryResources).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to ^[a-zA-Z0-9\+\/]*={0,3}$.
        /// </summary>
        internal static string RegularExpression_Base64String {
            get {
                return ResourceManager.GetString("RegularExpression_Base64String", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to ^(0(?:x|X))?([0-9a-fA-F]+)$.
        /// </summary>
        internal static string RegularExpression_HexadecimalString {
            get {
                return ResourceManager.GetString("RegularExpression_HexadecimalString", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid AES key..
        /// </summary>
        internal static string Validation_AESKey {
            get {
                return ResourceManager.GetString("Validation_AESKey", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to AES key not set; When instantiating this class with the constructor without the AES key, the SetOrUpdateKey(...) method must be called imediatelly before encrypting or decrypting data, providing a valid AES key..
        /// </summary>
        internal static string Validation_AESKeyNotSet {
            get {
                return ResourceManager.GetString("Validation_AESKeyNotSet", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Parameter &apos;{0}&apos; cannot be null or 0 length..
        /// </summary>
        internal static string Validation_ArgumentDataNullOrZeroLength {
            get {
                return ResourceManager.GetString("Validation_ArgumentDataNullOrZeroLength", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Parameter &apos;{0}&apos; cannot be null, empty or whitespace..
        /// </summary>
        internal static string Validation_ArgumentStringNullEmpytOrWhitespace {
            get {
                return ResourceManager.GetString("Validation_ArgumentStringNullEmpytOrWhitespace", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Data to decrypt is not valid (wrong size/length)..
        /// </summary>
        internal static string Validation_EncryptedDataSize {
            get {
                return ResourceManager.GetString("Validation_EncryptedDataSize", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Parameter &apos;{0}&apos; is not a valid base64 string..
        /// </summary>
        internal static string Validation_InvalidBase64String {
            get {
                return ResourceManager.GetString("Validation_InvalidBase64String", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Parameter &apos;{0}&apos; is not a valid hexadecimal string..
        /// </summary>
        internal static string Validation_InvalidHexadecimalString {
            get {
                return ResourceManager.GetString("Validation_InvalidHexadecimalString", resourceCulture);
            }
        }
    }
}
