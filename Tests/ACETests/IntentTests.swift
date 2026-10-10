import Testing
@testable import ACE

@Suite("Operation identity")
struct IntentTests {
    @Test func crossSDKNumbersAndUnicode() throws {
        let value: JSONValue = ["z": [nil, true, false, -0.0, 1.0, 1e-7, 1e21, "1"], "\u{e000}": "private", "😀": "中文/\n"]
        #expect(try intentDigest(value) == "5755ebae76cfdbfc522994dc18b9bba626d19aef7c98638c44a0ba8c852de634")
        #expect(try intentDigest(["a": 1]) == "2317a230dd89e93a9aee06850327e78f32a0e7ccbca1771fcf4d3ae16478eb2c")
        let reordered: JSONValue = ["😀": "中文/\n", "\u{e000}": "private", "z": [nil, true, false, 0, 1, 0.0000001, 1e21, "1"]]
        #expect(try intentDigest(reordered) == intentDigest(value))
    }

    @Test func typesStayDistinct() throws {
        let values: [JSONValue] = [.null, false, 0, "0", .array([]), .object([:]), ["number", "0000000000000000"]]
        #expect(try Set(values.map(intentDigest)).count == 7)
    }
}
