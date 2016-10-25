'use strict';

var assert = require('assert')
var disposable = require('../disposable')

describe('disposable', function() {
  describe('sync', function() {
    it('should validate domain/email: legit', function() {
      assert.equal(disposable.validate('gmail.com'), true)
      assert.equal(disposable.validate('foo@gmail.com'), true)
    })

    it('should validate domain/email: disposable', function() {
      assert.equal(disposable.validate('zoemail.com'), false)
      assert.equal(disposable.validate('foo@zoemail.com'), false)
    })
  })

  describe('async', function() {
    it('should validate domain: legit', function(done) {
      disposable.validate('gmail.com', function(err, result) {
        if (err) return done(err)
        assert.equal(result, true)
        done()
      })
    })

    it('should validate domain: disposable', function(done) {
      disposable.validate('zoemail.com', function(err, result) {
        if (err) return done(err)
        assert.equal(result, false)
        done()
      })
    })
  })
})
