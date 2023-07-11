import Foundation
import MdocDataModel18013

extension MdocSecurity18013Tests {
    enum AnnexdTestData {

		//D.5.1 Session encryption
		static let d51_sessionEstablishData = Data(base64Encoded: "omplUmVhZGVyS2V52BhYS6QBAiABIVggYOM5I4UEH1FAMFHyQVUxy1bdP5mccWhwE6rGdovIGH4iWCDljeuP2+kH991TaCRVUaNHlvfSIVxEDDObsPe2e+zN+mRkYXRhWQLfUq2irL62w5DyygvGWbSEZ465TdRQdDhqreziN3e0RgbkLihGvC4u48HoZ7HRaF5BNUoCGrsP2jbwnPXVxRtWHTvkHJNHrnHPK0nenex7RARqsCJHkxshDJFXhAwVFKYCewiBBxat9hlmNEl5MUrDrp9A5m4BXBJUpoQQi9CT6HcuwzP7Zj/WgDrwLqEL2+g6mZ91tVoYD4chOftXrASs1YyhXsoVDN4cO4SUARiLejDOiH3XtxsS7aL8bsblI1pslJg1H80wHyKSpOu6dVUoXO6E6tlu8Wd7Cvgjn2p6Uq9LiAmx1SqyGhYsoxreIcV70dmXCigyqsQcfVLRxP7k7mQDCiGN9RNjvnAXkvpsUVxIm9Odytb7pI8dbrGenHaVMaO/mZijLAGEEwXyOETKPbah/w0NkXND1i/HKtWOqwGjGYEW8ZYGYJ+U416st40jxZxnhSo2GRX+h4SM26VjDJn6txrv9y0THPRCZU93COxIIWQW8tmWz2z5EBK3cbiJB7HRYp36eUND5lPDEgdILi9mIc1LXc87PDKGJcM/6YvpnF8mSiZDFb5Buv3HJvi83lkg3gpxiE2GCvRMH/Gz14sujXINhdrlP+orP6GAYWKkvgLQOVZ8XrJBnCrYea9I/LffVcqU8bAPYhh/ojKcgieq4BMOwFLKPiEC5X5ykRsyjP3Puq9rk2RmD2E0FTgmRMMMC9TiIsXPlLpac2ecU9XO2VylB4fCKJoMFzWDk8Hg8icjYQAvubFgYGiIpZ73osOJ9ot8tCRXLbAmsXzyvcr8tnyCktkrUAUDVpAKYqgrFvhUdZBSsA8PRnOkYin0Mlfo6DJUAbP+zIxtIli69/fC+7r6s6G2re1Ozqwer9W2ERjfk7wKYisDUE/eR867Ik6YPbEmd+MWwiquBC1s5K2uDYsPQEN7jhr6CFnJUBvrY5dEloWaYPEQabGWW0/6xXealhkfierHyqaIueZ8")!
		
		static let d51_sessionData = Data(base64Encoded: "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")!

		  static let d51_sessionTermination = Data(base64Encoded: "oWZzdGF0dXMU")!

		  static let d51_sessionTranscriptData = Data(base64Encoded: "2BhZAkGD2BhYWKIAYzEuMAGCAdgYWEukAQIgASFYIFqI0YK85fQu+lmUPzM1nS6Klo/yidk+X6REtiQ0MWf+IlggsW6M+Fjdx2kEB7ph1MM4I3qM/PPeaqZy/GClV6oy/GfYGFhLpAECIAEhWCBg4zkjhQQfUUAwUfJBVTHLVt0/mZxxaHATqsZ2i8gYfiJYIOWN64/b6Qf33VNoJFVRo0eW99IhXEQMM5uw97Z77M36gljDkQIPSHMV0QIJYWMBATABBG1kb2MaIAwBYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoEos3KCgBAhwBXB5YBGlzby5vcmc6MTgwMTM6ZGV2aWNlZW5nYWdlbWVudG1kb2OiAGMxLjABggHYGFhLpAECIAEhWCBaiNGCvOX0LvpZlD8zNZ0uipaP8onZPl+kRLYkNDFn/iJYILFujPhY3cdpBAe6YdTDOCN6jPzz3mqmcvxgpVeqMvxnWM2RAiVIchWRAgJjcgECEQIEYWMBATAAEQIGYWMBA25mYwBRAgRhYwEBVwAaIB4BYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoB4CAvygBAhwCEQfIMv/20m+gvrNN/NVV1II6HBEBA2lzby5vcmc6MTgwMTM6bmZjbmZjAVoXKwFhcHBsaWNhdGlvbi92bmQud2ZhLm5hblcDAQEDIwIAEyT+yacLl6yWhKTjJhdu9bmBxehTPl8AKYz8y8NecAprAgQU")!
	static let d51_ephDeviceKey = CoseKeyPrivate(x: "5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe".toBytes()!, y:"b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67".toBytes()!, d:"c1917a1579949a042f1ba9fc53a2df9b1bc47adf31c10f813ed75702d1c1f136".toBytes()!)
	static let d51_ephReaderKey = CoseKeyPrivate(x: "60e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e".toBytes()!, y:"e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa".toBytes()!, d:"de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c".toBytes()!)
		
		
		//D.5.2 Issuer data authentication
	static let d52_iaca = Data(base64Encoded: "MIIBzjCCAXOgAwIBAgIUKrTt0FKyWC9Matlhht5w9N5aOZQwCgYIKoZIzj0EAwIwIzEUMBIGA1UEAwwLdXRvcGlhIGlhY2ExCzAJBgNVBAYTAlVTMB4XDTIwMTAwMTAwMDAwMFoXDTI5MDkyOTAwMDAwMFowIzEUMBIGA1UEAwwLdXRvcGlhIGlhY2ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELD4QPbwHslxadwru36XYvRVBfj5nYUJGGnh147QYiiIh5kI1mdHbGarvZvkj05S2FwlUm87C6m/2DsdSaPLglKOBhDCBgTAeBgNVHRIEFzAVgRNleGFtcGxlQGV4YW1wbGUuY29tMBwGA1UdHwQVMBMwEaAPoA2CC2V4YW1wbGUuY29tMB0GA1UdDgQWBBRU+iODoEwo4NkweSJhyAxIgdLACzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQDAgNJADBGAiEA7Il/C4rlECgoiVUDH4YAaWWbdZia9xKfpgnCQpmlx4cCIQDQiNh0H10Fs2DvboUCPpDfHTHdHmcBqI7+mnEDAh+YbA==")!
	
	static let d52_issuerAuthCBOR = Data(base64Encoded: "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")!
   // The following intermediate cryptographic data was used:
	static let d52_sigStructure = Data(base64Encoded: "hGpTaWduYXR1cmUxQ6EBJkBZA6LYGFkDnaZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzonFvcmcuaXNvLjE4MDEzLjUuMa0AWCB1FnMztHtsK/uG7MwfQ4z1evBVNxrFXh41niDyVK3OvwFYIGflOdYTnr0TGu9EG0RWRd2DGys3WzkMpe9iebIF7UVxAlggM5Q3Ldt4BT821dhpeA5h7aMT1Eo5IJKtjgUnovv+Va4DWCAuNa08TlFLtnsanbUc505MubcUbkGsUtrJzoa4YT21VQRYIOpcMwS7fEqNy1HEwTtlJk+EVUE0E0IJPMp4bgWPrC1ZBVgg+uSH9ot6DoenSXdOVunh3DqOx7d+SQ0h8OHTR1Zhqh0GWCB9g+UHrnfbgV3k2AO4hVXQUR2JTIl0OfV3QFZBahx1MwdYIPBUmhRfHPdcvu/6iB1IV91DjWJ88yF0sXMcTDjhLKk2CFggtoyK/LKq98WBQR0od97xVb4usSGkK8m6W3MSN34Gj2YJWCALNYfR3QwqB6Nb+xINmaCr+131aGW7f6FcyLVqZt9uDApYIMmKFwzzbhGrtyTpinWlND36K27T3y7Pu47y7lXdQciBC1ggtX3QNngvexTGow+qqubM1QVM6IvfpRoBa6de2h7eqUgMWCBlH4c2sYSA/iUqAyJOoIe10QylSFFGxnx0rE7DES1MOnRvcmcuaXNvLjE4MDEzLjUuMS5VU6QAWCDYC4PSUXPEhMVkBhD/GjHJScHZNL9M9/GNUiOxXdTyHAFYIE2A4eLk+yRtl4lUJ85wALtZuyTIzQA+z5S/NbvSkX40AlggizMfO2hbyjcuhTUaJclISrevzfDSIzEFUR93jZjC9UQDWCDDQ68b0WkHFUORYaunNwLEdKv5krIMn7VcNqM26+Aah21kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIJYxPWxj4k4zcnQr/bGjO6LIl9zWirjHU+T71I3Ka3+aIlggH7Mmnt1BiFfeGzmk5KRLkvpITKpyLCKCiPAdDAOiw9ZnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjAtMTAtMDFUMTM6MzA6MDJaaXZhbGlkRnJvbcB0MjAyMC0xMC0wMVQxMzozMDowMlpqdmFsaWRVbnRpbMB0MjAyMS0xMC0wMVQxMzozMDowMlo=")!

	static let d52_nfcHandoverRequest = Data(base64Encoded: "kQIlSHIVkQICY3IBAhECBGFjAQEwABECBmFjAQNuZmMAUQIEYWMBAVcAGiAeAWFwcGxpY2F0aW9uL3ZuZC5ibHVldG9vdGgubGUub29iMAgbKAeAgL8oAQIcAhEHyDL/9tJvoL6zTfzVVdSCOhwRAQNpc28ub3JnOjE4MDEzOm5mY25mYwFaFysBYXBwbGljYXRpb24vdm5kLndmYS5uYW5XAwEBAyMCABMk/smnC5esloSk4yYXbvW5gcXoUz5fACmM/MvDXnAKawIEFA==")!

	static let d52_nfcHandoverSelect = Data(base64Encoded: "kQIPSHMV0QIJYWMBATABBG1kb2MaIAwBYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoEos3KCgBAhwBXB5YBGlzby5vcmc6MTgwMTM6ZGV2aWNlZW5nYWdlbWVudG1kb2OiAGMxLjABggHYGFhLpAECIAEhWCBaiNGCvOX0LvpZlD8zNZ0uipaP8onZPl+kRLYkNDFn/iJYILFujPhY3cdpBAe6YdTDOCN6jPzz3mqmcvxgpVeqMvxn")!

	// D.5.3 mdoc authentication
	static let d53_deviceKey = CoseKeyPrivate(x: "96313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a".toBytes()!, y: "1fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d6".toBytes()!, d: "6ed542ad4783f0b18c833fadf2171273a35d969c581691ef704359cc7cf1e8c0".toBytes()!) 
  static let d53_deviceAuth = Data(base64Encoded: "oWlkZXZpY2VNYWOEQ6EBBaD2WCDplSGoWteJG4BqB/i1OIozLZLBiae/KT7h9UNAWuaCTQ==")!
  /* The following intermediate cryptographic data was used:
   EMacKey Zab: 78d98a86fbbb82895874bfafcc161ba69f9b77662172c74b3b0d4643276cf991
   EMacKey key: dc2b9566fdaaae3c06baa40993cd0451aeba15e7677ef5305f6531f3533c35dd
   MAC tag: e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d */
  //DeviceAuth = { ; Either signature or MAC for mdoc authentication"deviceSignature" : DeviceSignature or "deviceMac" : DeviceMac }
  static let d53_deviceAuthDeviceAuthenticationBytes = Data(base64Encoded: "2BhZAnGEdERldmljZUF1dGhlbnRpY2F0aW9ug9gYWFiiAGMxLjABggHYGFhLpAECIAEhWCBaiNGCvOX0LvpZlD8zNZ0uipaP8onZPl+kRLYkNDFn/iJYILFujPhY3cdpBAe6YdTDOCN6jPzz3mqmcvxgpVeqMvxn2BhYS6QBAiABIVggYOM5I4UEH1FAMFHyQVUxy1bdP5mccWhwE6rGdovIGH4iWCDljeuP2+kH991TaCRVUaNHlvfSIVxEDDObsPe2e+zN+oJYw5ECD0hzFdECCWFjAQEwAQRtZG9jGiAMAWFwcGxpY2F0aW9uL3ZuZC5ibHVldG9vdGgubGUub29iMAgbKBKLNygoAQIcAVweWARpc28ub3JnOjE4MDEzOmRldmljZWVuZ2FnZW1lbnRtZG9jogBjMS4wAYIB2BhYS6QBAiABIVggWojRgrzl9C76WZQ/MzWdLoqWj/KJ2T5fpES2JDQxZ/4iWCCxboz4WN3HaQQHumHUwzgjeoz8895qpnL8YKVXqjL8Z1jNkQIlSHIVkQICY3IBAhECBGFjAQEwABECBmFjAQNuZmMAUQIEYWMBAVcAGiAeAWFwcGxpY2F0aW9uL3ZuZC5ibHVldG9vdGgubGUub29iMAgbKAeAgL8oAQIcAhEHyDL/9tJvoL6zTfzVVdSCOhwRAQNpc28ub3JnOjE4MDEzOm5mY25mYwFaFysBYXBwbGljYXRpb24vdm5kLndmYS5uYW5XAwEBAyMCABMk/smnC5esloSk4yYXbvW5gcXoUz5fACmM/MvDXnAKawIEFHVvcmcuaXNvLjE4MDEzLjUuMS5tREzYGEGg")!
  static let d53_deviceAuthMacStructure = Data(base64Encoded:"hGRNQUMwQ6EBBUBZAnbYGFkCcYR0RGV2aWNlQXV0aGVudGljYXRpb26D2BhYWKIAYzEuMAGCAdgYWEukAQIgASFYIFqI0YK85fQu+lmUPzM1nS6Klo/yidk+X6REtiQ0MWf+IlggsW6M+Fjdx2kEB7ph1MM4I3qM/PPeaqZy/GClV6oy/GfYGFhLpAECIAEhWCBg4zkjhQQfUUAwUfJBVTHLVt0/mZxxaHATqsZ2i8gYfiJYIOWN64/b6Qf33VNoJFVRo0eW99IhXEQMM5uw97Z77M36gljDkQIPSHMV0QIJYWMBATABBG1kb2MaIAwBYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoEos3KCgBAhwBXB5YBGlzby5vcmc6MTgwMTM6ZGV2aWNlZW5nYWdlbWVudG1kb2OiAGMxLjABggHYGFhLpAECIAEhWCBaiNGCvOX0LvpZlD8zNZ0uipaP8onZPl+kRLYkNDFn/iJYILFujPhY3cdpBAe6YdTDOCN6jPzz3mqmcvxgpVeqMvxnWM2RAiVIchWRAgJjcgECEQIEYWMBATAAEQIGYWMBA25mYwBRAgRhYwEBVwAaIB4BYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoB4CAvygBAhwCEQfIMv/20m+gvrNN/NVV1II6HBEBA2lzby5vcmc6MTgwMTM6bmZjbmZjAVoXKwFhcHBsaWNhdGlvbi92bmQud2ZhLm5hblcDAQEDIwIAEyT+yacLl6yWhKTjJhdu9bmBxehTPl8AKYz8y8NecAprAgQUdW9yZy5pc28uMTgwMTMuNS4xLm1ETNgYQaA=")!
  static let d53_deviceAuthCBORdata = Data(base64Encoded: "oWlkZXZpY2VNYWOEQ6EBBaD2WCDplSGoWteJG4BqB/i1OIozLZLBiae/KT7h9UNAWuaCTQ==")!
  // D.5.4 mdoc reader authentication
  static let d54_readerRoot = Data(base64Encoded:  "MIIBkDCCATegAwIBAgIUMNdHeVQF1WS3rEi+bzZK4sd08vwwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLcmVhZGVyIHJvb3QwHhcNMjAxMDAxMDAwMDAwWhcNMjkwOTI5MDAwMDAwWjAWMRQwEgYDVQQDDAtyZWFkZXIgcm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDZDKTgy4KSA3lkt8HCP4ltrkj9jl6s5qLG3REWTrbicd7fpwoz0jW0Ye0PJv3ucLFxe8i8ynkTnqRtHRbfiBjqjYzBhMBwGA1UdHwQVMBMwEaAPoA2CC2V4YW1wbGUuY29tMB0GA1UdDgQWBBTPt6iBuupfMrb7kcwpWQxQ36xBbjAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQDAgNHADBEAiAYrIS6+ZGmFPsl52JBhXt/0Fed/ortisfxMGdUkHmZMAIgd/RvALSvPgFNJT4O3MnxRqdaaxvf4z6fpy8w8IgNUjc=")!
  
  static let d54_readerAuth =  Data(base64Encoded:  "hEOhASahGCFZAbcwggGzMIIBWKADAgECAhR1UnFfat0yPUk0oboXXclFdV2LUDAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtyZWFkZXIgcm9vdDAeFw0yMDEwMDEwMDAwMDBaFw0yMzEyMzEwMDAwMDBaMBExDzANBgNVBAMMBnJlYWRlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPiRLuD5Era+aDui+gEhsmMOYBsrYo3/O0T2OU6qmr28whSdKdb/Gj4JETUXflw9nFfzv4OXYe7QLGTdgq4dO7+jgYgwgYUwHAYDVR0fBBUwEzARoA+gDYILZXhhbXBsZS5jb20wHQYDVR0OBBYEFPLfxKyvxfMLRk+togv81TOvXgf1MB8GA1UdIwQYMBaAFM+3qIG66l8ytvuRzClZDFDfrEFuMA4GA1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQEGMAoGCCqGSM49BAMCA0kAMEYCIQD7nqO2hv1+ovAjSFj/gyi07+9qHvcexKrk4wcgb5IUkwIhAJuU8Nc536hMyinv7VKd1IOKz9i2vuIS3GMgxG/rg5o19lhAHzQABpBjwYkTi9zS9jFCfFiUJBE/yewmzrysrPzblpXSjpmVO+yrxOMKtO+syDmoH5FZkz0ZJSfukbRJu3+Avw==")!
  
  static let d54_ReaderAuthenticationBytes =  Data(base64Encoded: "2BhZAu6DdFJlYWRlckF1dGhlbnRpY2F0aW9ug9gYWFiiAGMxLjABggHYGFhLpAECIAEhWCBaiNGCvOX0LvpZlD8zNZ0uipaP8onZPl+kRLYkNDFn/iJYILFujPhY3cdpBAe6YdTDOCN6jPzz3mqmcvxgpVeqMvxn2BhYS6QBAiABIVggYOM5I4UEH1FAMFHyQVUxy1bdP5mccWhwE6rGdovIGH4iWCDljeuP2+kH991TaCRVUaNHlvfSIVxEDDObsPe2e+zN+oJYw5ECD0hzFdECCWFjAQEwAQRtZG9jGiAMAWFwcGxpY2F0aW9uL3ZuZC5ibHVldG9vdGgubGUub29iMAgbKBKLNygoAQIcAVweWARpc28ub3JnOjE4MDEzOmRldmljZWVuZ2FnZW1lbnRtZG9jogBjMS4wAYIB2BhYS6QBAiABIVggWojRgrzl9C76WZQ/MzWdLoqWj/KJ2T5fpES2JDQxZ/4iWCCxboz4WN3HaQQHumHUwzgjeoz8895qpnL8YKVXqjL8Z1jNkQIlSHIVkQICY3IBAhECBGFjAQEwABECBmFjAQNuZmMAUQIEYWMBAVcAGiAeAWFwcGxpY2F0aW9uL3ZuZC5ibHVldG9vdGgubGUub29iMAgbKAeAgL8oAQIcAhEHyDL/9tJvoL6zTfzVVdSCOhwRAQNpc28ub3JnOjE4MDEzOm5mY25mYwFaFysBYXBwbGljYXRpb24vdm5kLndmYS5uYW5XAwEBAyMCABMk/smnC5esloSk4yYXbvW5gcXoUz5fACmM/MvDXnAKawIEFNgYWJOiZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xpmtmYW1pbHlfbmFtZfVvZG9jdW1lbnRfbnVtYmVy9XJkcml2aW5nX3ByaXZpbGVnZXP1amlzc3VlX2RhdGX1a2V4cGlyeV9kYXRl9Whwb3J0cmFpdPQ=")!
  
  static let d54_ReaderSigStructure =  Data(base64Encoded: "hGpTaWduYXR1cmUxQ6EBJkBZAvPYGFkC7oN0UmVhZGVyQXV0aGVudGljYXRpb26D2BhYWKIAYzEuMAGCAdgYWEukAQIgASFYIFqI0YK85fQu+lmUPzM1nS6Klo/yidk+X6REtiQ0MWf+IlggsW6M+Fjdx2kEB7ph1MM4I3qM/PPeaqZy/GClV6oy/GfYGFhLpAECIAEhWCBg4zkjhQQfUUAwUfJBVTHLVt0/mZxxaHATqsZ2i8gYfiJYIOWN64/b6Qf33VNoJFVRo0eW99IhXEQMM5uw97Z77M36gljDkQIPSHMV0QIJYWMBATABBG1kb2MaIAwBYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoEos3KCgBAhwBXB5YBGlzby5vcmc6MTgwMTM6ZGV2aWNlZW5nYWdlbWVudG1kb2OiAGMxLjABggHYGFhLpAECIAEhWCBaiNGCvOX0LvpZlD8zNZ0uipaP8onZPl+kRLYkNDFn/iJYILFujPhY3cdpBAe6YdTDOCN6jPzz3mqmcvxgpVeqMvxnWM2RAiVIchWRAgJjcgECEQIEYWMBATAAEQIGYWMBA25mYwBRAgRhYwEBVwAaIB4BYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoB4CAvygBAhwCEQfIMv/20m+gvrNN/NVV1II6HBEBA2lzby5vcmc6MTgwMTM6bmZjbmZjAVoXKwFhcHBsaWNhdGlvbi92bmQud2ZhLm5hblcDAQEDIwIAEyT+yacLl6yWhKTjJhdu9bmBxehTPl8AKYz8y8NecAprAgQU2BhYk6JnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGma2ZhbWlseV9uYW1l9W9kb2N1bWVudF9udW1iZXL1cmRyaXZpbmdfcHJpdmlsZWdlc/VqaXNzdWVfZGF0ZfVrZXhwaXJ5X2RhdGX1aHBvcnRyYWl09A==")!
  
  static let d54_jws = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCN3pDQ0FaYWdBd0lCQWdJVUZhcDZiTHFRT0h0NGROZXNvUy9EYm9IU1BjMHdDZ1lJS29aSXpqMEVBd0l3SXpFVU1CSUdBMVVFQXd3TGRYUnZjR2xoSUdsaFkyRXhDekFKQmdOVkJBWVRBbFZUTUI0WERUSXdNVEF3TVRBd01EQXdNRm9YRFRJeE1UQXdNVEF3TURBd01Gb3dJakVUTUJFR0ExVUVBd3dLZFhSdmNHbGhJR3AzY3pFTE1Ba0dBMVVFQmhNQ1ZWTXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUzRLYTVzUUtCOHQ2b0JJMjM4bXRkOFdRaTdoRWhsNE1YQ21jU0V5a3hUbzdjNUVndHRHQnkxRm5yS1BXQlo4MXFJcXpubzNQdDNyRVhpSUw3cHhHUERvNEdvTUlHbE1CNEdBMVVkRWdRWE1CV0JFMlY0WVcxd2JHVkFaWGhoYlhCc1pTNWpiMjB3SEFZRFZSMGZCQlV3RXpBUm9BK2dEWUlMWlhoaGJYQnNaUzVqYjIwd0hRWURWUjBPQkJZRUZPR3RtWFAxUmZxdjhmeW9BcFBUVyswa2ttc3BNQjhHQTFVZEl3UVlNQmFBRkZUNkk0T2dUQ2pnMlRCNUltSElERWlCMHNBTE1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBVkJnTlZIU1VCQWY4RUN6QUpCZ2NvZ1l4ZEJRRURNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQ1Q5OU5zREsxeGhlWFcyTTNVcmVzNzhOYlVuNGFyRjh6K1RDZ0VvWlF3VkFpQjRiL1Uxazg4V0hEK01sZmxiM0NkSHpQd1RoNmZGYVAycGFMVnZRZHJsZHc9PSJdfQ.eyJkb2N0eXBlIjoib3JnLmlzby4xODAxMy41LjEubURMIiwibmFtZXNwYWNlcyI6eyJvcmcuaXNvLjE4MDEzLjUuMSI6eyJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmVuX25hbWUiOiJKYW5lIiwiaXNzdWVfZGF0ZSI6IjIwMTktMTAtMjAiLCJleHBpcnlfZGF0ZSI6IjIwMjQtMTAtMjAiLCJkb2N1bWVudF9udW1iZXIiOiIxMjM0NTY3ODkiLCJwb3J0cmFpdCI6Il85al80QUFRU2taSlJnQUJBUUVBa0FDUUFBRF8yd0JEQUJNTkRoRU9EQk1SRHhFVkZCTVhIVEFmSFJvYUhUb3FMQ013UlQxSlIwUTlRMEZNVm0xZFRGRm9Va0ZEWDRKZ2FIRjFlM3g3U2x5R2tJVjNqMjE0ZTNiXzJ3QkRBUlFWRlIwWkhUZ2ZIemgyVDBOUGRuWjJkbloyZG5aMmRuWjJkbloyZG5aMmRuWjJkbloyZG5aMmRuWjJkbloyZG5aMmRuWjJkbloyZG5aMmRuWjJkbmJfd0FBUkNBQVlBR1FEQVNJQUFoRUJBeEVCXzhRQUd3QUFBd0VBQXdFQUFBQUFBQUFBQUFBQUFBVUdCQUVDQXdmX3hBQXlFQUFCQXdNREFnVUNBd2tBQUFBQUFBQUJBZ01FQUFVUkJoSWhFekVVRlZGaGNTSkJCNEdoRmpWQ1VuT1Jzc0h4XzhRQUZRRUJBUUFBQUFBQUFBQUFBQUFBQUFBQUFBSF94QUFhRVFFQkFRQURBUUFBQUFBQUFBQUFBQUFBQVVFUklURmhfOW9BREFNQkFBSVJBeEVBUHdDbHU5NGkyaU1weDlhU3ZIME5BX1VzLXdfM1hucC04LWR3bHlPaDBOcmhSdDM3czhBNXpnZXRLOVI2ZmpMYnVOMGRVdGJ2U3loUFpLU0FCbjM3VWZoXy01WF9BT3VmOFUwaFhlWnE4SW5PUkxmYjNweTJpUW9vT08zZkdBZVBldDFpMUJIdlRibXhDbVhXdVZvVWM0SHFEVWxia3pKMV9tdTZkY0VVRUVxTHBCQkJQcGc5X3dCUFd2WFRTMHRNM21NdENfSDlGWks5MlJ4a0VmT1RUQy1tcjJ0VWwxMFFiYzlLWmE1VzZGWUFIcndEeDg0cDNaN3ZIdkVQeEVmY25hZHEwcTdwTlRlaHVuNVBjTjJPX3dCWHh0XzdYaG9aaFVxRGRZNVVVb2RRbEc3R2NFaFF6UU43enJDTGJYMHN4MjB6Rl94N1hNQlB0bkJ5YWNYRzRNVzJDdVZKSkNFanNPU1Q5Z0tnZFZXZU5abHcyWTI0bFNWRmExSEpVY2l2b1Q2bzZZNDhXV2cyZUQxY1lfV21HcG45dHlrSWRkdEw2SXF6aEx1N3Y4Y1lQOTZxWXo2SlVkdDlvNWJjU0ZKUHNhaTlZUnBhb3FKREx6Q3JRZ3A2YlRKQXh4alBBeC1wNzB5YTFWQWdXcUFwVWQ5S0hXeUVJYkFWdDJuYmpKSXBnMzZpdm9zYkRUblE2Nm5GRklUdjI0d09fWTBsamE4OFJKYVo4dTI5UllUbnI1eGs0X2xybS1zbzFLeEFreDVrZU1qbmFpU29KVVNWQWRobjBySGMzcnJwbTV4MUt1VHMxdDNrb1huQndlUmdrNC1SU2U5bFhsRmNBNUdhS0p5ejNLSjQtM3Z4ZF9UNnFDbmRqT1B5ckpwLXplU1FseC12MTl6aFh1MmJjY0FZeGstbEZGRkxKT2prLU1YSnQxd2VnbGVkd1NNOV9zQ0NPUGF0MWkwNUdzd2NVbGFubm5CdFV0UXh4NkFVVVVDNV9SU2VzNllOeGVpTXU4TGFDU1FSNmR4eDg1cDNaclJIczBUb1I5eXNuY3RhdTZqUlJRWWRRNmI4OGVaYzhWME9rQ01kUGRuUDVpbVZ4dHpGeWhLaXlRU2hYM0hkSjlSUlJUNEowYUlVVUpZY3V6Nm9xVlpETzNnZkhPTTlfdFZQRGl0UW9yY2RoTzF0c1lBb29vRjE5MF9HdmFFRnhTbW5rY0pjVHp4NkVmY1ZoaWFQU21hM0p1TTk2ZXB2RzFLeGdjZGdjazVIdFJSU0Nsb29vb1BfMlEiLCJkcml2aW5nX3ByaXZpbGVnZXMiOlt7InZlaGljbGVfY2F0ZWdvcnlfY29kZSI6IkEiLCJpc3N1ZV9kYXRlIjoiMjAxOC0wOC0wOSIsImV4cGlyeV9kYXRlIjoiMjAyNC0xMC0yMCJ9LHsidmVoaWNsZV9jYXRlZ29yeV9jb2RlIjoiQiIsImlzc3VlX2RhdGUiOiIyMDE3LTAyLTIzIiwiZXhwaXJ5X2RhdGUiOiIyMDI0LTEwLTIwIn1dfX0sImlhdCI6MTYwOTg1NTIwMCwiZXhwIjoxNjA5ODU1MzIwfQ.JRjQgYpNthh52j3xQ1f6tkoKRBsF8YwH6NlKYg2n_pyayOoQyrRPO0aPBeVJ5lgKBzLumjamuvr3C824R_RYHQ"
 static let request_d411 = Data(base64Encoded: "omd2ZXJzaW9uYzEuMGtkb2NSZXF1ZXN0c4GibGl0ZW1zUmVxdWVzdNgYWJOiZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xpmtmYW1pbHlfbmFtZfVvZG9jdW1lbnRfbnVtYmVy9XJkcml2aW5nX3ByaXZpbGVnZXP1amlzc3VlX2RhdGX1a2V4cGlyeV9kYXRl9Whwb3J0cmFpdPRqcmVhZGVyQXV0aIRDoQEmoRghWQG3MIIBszCCAVigAwIBAgIUdVJxX2rdMj1JNKG6F13JRXVdi1AwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLcmVhZGVyIHJvb3QwHhcNMjAxMDAxMDAwMDAwWhcNMjMxMjMxMDAwMDAwWjARMQ8wDQYDVQQDDAZyZWFkZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT4kS7g+RK2vmg7ovoBIbJjDmAbK2KN/ztE9jlOqpq9vMIUnSnW/xo+CRE1F35cPZxX87+Dl2Hu0Cxk3YKuHTu/o4GIMIGFMBwGA1UdHwQVMBMwEaAPoA2CC2V4YW1wbGUuY29tMB0GA1UdDgQWBBTy38Ssr8XzC0ZPraIL/NUzr14H9TAfBgNVHSMEGDAWgBTPt6iBuupfMrb7kcwpWQxQ36xBbjAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH/BAswCQYHKIGMXQUBBjAKBggqhkjOPQQDAgNJADBGAiEA+56jtob9fqLwI0hY/4MotO/vah73HsSq5OMHIG+SFJMCIQCblPDXOd+oTMop7+1SndSDis/Ytr7iEtxjIMRv64OaNfZYQB80AAaQY8GJE4vc0vYxQnxYlCQRP8nsJs68rKz825aV0o6ZlTvsq8TjCrTvrMg5qB+RWZM9GSUn7pG0Sbt/gL8=")!
    }
    
}